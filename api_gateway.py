#API Gateway

import os
import json
import time
from typing import Optional

import httpx
from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
import jwt
app = FastAPI()

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8001")
CHAT_SERVICE_URL = os.getenv("CHAT_SERVICE)URL", "http://loccalhost:8002")
CONTENT_SERVICE_URL = os.getenv("CONTENT_SERVICE_URL", "http://localhost:8003")

async def forward_request(service_url: str, request: Request):
    async with httpx.AsyncClient() as client:

        url = f"{service_url}{request.url.path}"
        # Forward headers and query params
        headers = dict(request.headers)
        data = await request.body()
        response = await client.request(
            request.method,
            url,
            headers = headers,
            params = request.query_params,
            content = data
        )
        return response
    
@app.api_route("/auth/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def auth_proxy(path: str, request: Request):
    response = await forward_request(AUTH_SERVICE_URL, request)
    return response.text, response.status_code

@app.api_route("/chat/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def chat_proxy(path: str, request: Request):
    response = await forward_request(CHAT_SERVICE_URL, request)
    return response.text, response.status_code

@app.api_route("/content/{path:path}", methods=["GET", "POST", "PUT", "DELETE"])
async def content_proxy(path: str, request: Request):
    response = await forward_request(CONTENT_SERVICE_URL, request)
    return response.text, response.status_code