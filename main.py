# main.py

from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
import time

from database import SessionLocal
from models import ActivationKeyDB
from activation_key_manager import (
    create_new_activation_key,
    decode_token,
    set_agent_deployed
)

app = FastAPI()

SERVER_SECRET = "SUPER_SECRET_123"  # Load from environment in production

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/generate-activation-key")
def generate_activation_key(db: Session = Depends(get_db)):
    """
    Creates a brand-new key with agent_deployed=0 and stores it in the DB.
    Returns the full token to the caller.
    """
    full_token = create_new_activation_key(SERVER_SECRET)

    # Decode it to retrieve timestamps and agent state, for storing in DB
    payload = decode_token(full_token, SERVER_SECRET)

    db_key = ActivationKeyDB(
        full_token=full_token,
        created_at=payload["created_at"],
        expires_at=payload["expires_at"],
        agent_deployed=payload["agent_deployed"]
    )
    db.add(db_key)
    db.commit()
    db.refresh(db_key)

    return {
        "id": db_key.id,
        "full_token": db_key.full_token,  # user must store this
        "agent_deployed": db_key.agent_deployed,
        "expires_at": db_key.expires_at
    }


@app.post("/deploy-agent")
def deploy_agent(full_token: str, db: Session = Depends(get_db)):
    """
    Sets agent_deployed=1 within the token, if it's currently 0.
    Then updates the token in DB and returns the new token.
    """
    # Lookup the record in the DB
    record = db.query(ActivationKeyDB).filter(
        ActivationKeyDB.full_token == full_token
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Activation key not found in database")

    # Decode the token (checks signature + expiration)
    try:
        payload = decode_token(record.full_token, SERVER_SECRET)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Check if already deployed
    if payload["agent_deployed"] == 1:
        # If you want to enforce "cannot re-deploy with the same key," raise error:
        raise HTTPException(status_code=403, detail="Agent is already deployed with this key")
    
    # Otherwise, set agent_deployed=1
    new_token = set_agent_deployed(record.full_token, SERVER_SECRET, deployed=True)

    # Update DB with the new token
    new_payload = decode_token(new_token, SERVER_SECRET)
    record.full_token = new_token
    record.agent_deployed = new_payload["agent_deployed"]
    db.commit()
    db.refresh(record)

    # Return the updated token so the user can use it for future requests
    return {
        "message": "Agent deployed successfully.",
        "full_token": record.full_token,
        "agent_deployed": record.agent_deployed,
        "expires_at": record.expires_at,
    }


@app.post("/stop-agent")
def stop_agent(full_token: str, db: Session = Depends(get_db)):
    """
    Sets agent_deployed=0 within the token, if it's currently 1.
    Then updates the token in DB and returns the new token.
    """
    record = db.query(ActivationKeyDB).filter(
        ActivationKeyDB.full_token == full_token
    ).first()
    if not record:
        raise HTTPException(status_code=404, detail="Activation key not found in database")

    # Decode the token (checks signature + expiration)
    try:
        payload = decode_token(record.full_token, SERVER_SECRET)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    if payload["agent_deployed"] == 0:
        # If you want to enforce "once an agent is started, can't revert to 0," you could do so:
        # raise HTTPException(status_code=403, detail="No agent is currently deployed.")
        pass

    # Otherwise, set agent_deployed=0
    new_token = set_agent_deployed(record.full_token, SERVER_SECRET, deployed=False)

    # Update DB with the new token
    new_payload = decode_token(new_token, SERVER_SECRET)
    record.full_token = new_token
    record.agent_deployed = new_payload["agent_deployed"]
    db.commit()
    db.refresh(record)

    return {
        "message": "Agent torn down successfully.",
        "full_token": record.full_token,
        "agent_deployed": record.agent_deployed,
        "expires_at": record.expires_at,
    }
