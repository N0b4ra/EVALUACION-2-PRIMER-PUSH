from fastapi import FastAPI
import os, secrets
from fastapi import (Depends, Header, HTTPException)

app = FastAPI(
    title = "BACKEND API en español",
    description="Api en el localhost enruta por API GATEWAT"
)

#SELINUX
INTERNAL_GATEWAY_SECRET = os.getenv(
    "INTERNAL_GATEWAY_SECRET"
)
if not INTERNAL_GATEWAY_SECRET:
    raise RuntimeError(
        "INTERNAL_GATEWAY_SECRET no esta configurado"
    )

def verify_gateway(
    x_gateway_secret : str = Header(default="")
):
    valid = secrets.compare_digest(
        x_gateway_secret,
        INTERNAL_GATEWAY_SECRET
    )
    if not valid:
        raise HTTPException(
            status_code=403,
            detail="Solicitud no autorizada"
        )

@app.get(
    "/salud",
    dependencies=[Depends(verify_gateway)]
         )
def salud(
    x_authenticated_client: str | None = Header(
        default=None
    )
):
    return {
        "authenticated_client": x_authenticated_client,
        "status": "OK",
        "service": "Backend API"
    }
@app.get(
    "/productos",
    dependencies=[Depends(verify_gateway)]
    )
def productos(
    x_authenticated_client: str | None = Header(
        default=None
):
    return {
        "authenticated_client": x_authenticated_client,
        "productos": [
            {"id": 1, "nombre":"nombredelproducto1", "precio":0},
            {"id": 2, "nombre": "nombre del producto 2", "precio":0}
        ]
    }
)
    
@app.get(
    "/ordenes",
    dependencies=[Depends(verify_gateway)]
    )
def ordenes(
    x_authenticated_client: str | None = Header(
        default=None
):
    return {
        "authenticated_client": x_authenticated_client,
        "ordenes":[
            {"id":1001, "estado":"pagado"},
            {"id":1002, "estado": "pendiente"}
        ]
    }
)