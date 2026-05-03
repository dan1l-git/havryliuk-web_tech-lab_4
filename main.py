import ssl
import asyncio
import json
import websockets as binance_ws
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Request, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from contextlib import asynccontextmanager
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
import httpx
import jwt
import message_pb2

# Конфігурація Casdoor
CASDOOR_URL = "https://localhost"
CLIENT_ID = "478ba06fe3d0ca347598"
CLIENT_SECRET = "8bbad2aab17704f41cf9279422865a55e7b9d7f9"
REDIRECT_URI = "http://localhost:8080/callback"


# --- ЛОГІКА WEBSOCKET ТА BINANCE ---

class ConnectionManager:
    def __init__(self):
        self.subscriptions: dict[str, set[WebSocket]] = {
            "BTCUSDT": set(),
            "ETHUSDT": set(),
            "SOLUSDT": set(),
            "BNBUSDT": set()
        }

    async def connect(self, websocket: WebSocket):
        await websocket.accept()

    def subscribe(self, websocket: WebSocket, symbol: str):
        if symbol in self.subscriptions:
            self.subscriptions[symbol].add(websocket)

    def unsubscribe(self, websocket: WebSocket):
        for symbol in self.subscriptions:
            self.subscriptions[symbol].discard(websocket)

    async def broadcast(self, symbol: str, data: dict):
        if symbol in self.subscriptions and self.subscriptions[symbol]:
            update = message_pb2.PriceUpdate()
            update.symbol = symbol
            update.price = str(data['p'])
            update.timestamp = str(data['E'])
            binary_data = update.SerializeToString()

            for connection in list(self.subscriptions[symbol]):
                try:
                    await connection.send_bytes(binary_data)
                except:
                    self.unsubscribe(connection)


manager = ConnectionManager()


async def binance_stream():
    url = "wss://stream.binance.com:9443/ws/btcusdt@trade/ethusdt@trade/solusdt@trade/bnbusdt@trade"
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            async with binance_ws.connect(url, ssl=ssl_context) as ws:
                while True:
                    res = await ws.recv()
                    data = json.loads(res)
                    symbol = data['s']
                    await manager.broadcast(symbol, data)
        except Exception as e:
            print(f"Binance connection error: {e}")
            await asyncio.sleep(5)


background_tasks = set()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(binance_stream())
    background_tasks.add(task)
    yield
    task.cancel()


# --- ІНІЦІАЛІЗАЦІЯ ДОДАТКУ (ОДИН РАЗ!) ---

app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="."), name="static")


# --- ДОПОМІЖНА ФУНКЦІЯ ДЛЯ ВАЛІДАЦІЇ JWT ---
async def verify_casdoor_token(token: str):
    """Отримує публічні ключі від Casdoor і локально перевіряє підпис токена"""
    async with httpx.AsyncClient(verify=False) as client:
        jwks_res = await client.get(f"{CASDOOR_URL}/.well-known/jwks")
        jwks_res.raise_for_status()

    jwks_data = jwks_res.json()

    public_keys = {}
    for jwk in jwks_data.get('keys', []):
        kid = jwk.get('kid', 'default_key')
        public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(jwk)

    if not public_keys:
        raise ValueError("Casdoor не повернув жодного JWK ключа")

    unverified_header = jwt.get_unverified_header(token)
    kid = unverified_header.get('kid', 'default_key')

    if kid in public_keys:
        key = public_keys[kid]
    else:
        key = list(public_keys.values())[0]

    payload = jwt.decode(
        token,
        key=key,
        algorithms=["RS256", "RS384", "RS512"],
        audience=CLIENT_ID,
        options={"verify_aud": False}
    )
    return payload


# --- ЕНДПОІНТИ ---

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/login")
async def login():
    auth_url = f"{CASDOOR_URL}/login/oauth/authorize?client_id={CLIENT_ID}&response_type=code&redirect_uri={REDIRECT_URI}&scope=read&state=casdoor"
    return RedirectResponse(auth_url)


@app.get("/callback")
async def callback(code: str):
    async with httpx.AsyncClient(verify=False) as client:
        token_res = await client.post(
            f"{CASDOOR_URL}/api/login/oauth/access_token",
            data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "code": code,
            }
        )
    token_data = token_res.json()
    access_token = token_data.get("access_token")
    redirect = RedirectResponse(url="/")
    redirect.set_cookie(key="access_token", value=access_token, httponly=False)
    return redirect


@app.get("/user-info")
async def user_info(request: Request):
    token = request.cookies.get("access_token")
    if not token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unauthorized")

    try:
        # Локальна валідація токена замість запиту до Casdoor
        payload = await verify_casdoor_token(token)
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid token: {e}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)

    token = websocket.query_params.get("token")
    if not token:
        token = websocket.cookies.get("access_token")

    if not token or token == "null":
        await websocket.close(code=1008)
        return

    try:
        # Локальна валідація токена перед підпискою на WebSockets
        payload = await verify_casdoor_token(token)
    except Exception as e:
        print(f"WebSocket Auth Error: {e}")
        await websocket.close(code=1008)  # 1008: Policy Violation
        return

    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("action") == "subscribe":
                manager.subscribe(websocket, message["symbol"])
            elif message.get("action") == "unsubscribe":
                manager.unsubscribe(websocket)

    except WebSocketDisconnect:
        manager.unsubscribe(websocket)