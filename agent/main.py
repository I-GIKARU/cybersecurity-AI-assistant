from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from core.cybersecurity_agent import CybersecurityAgent
import uvicorn

app = FastAPI(title="Cybersecurity AI Agent", version="1.0.0")
agent = CybersecurityAgent()

class QueryRequest(BaseModel):
    message: str

class QueryResponse(BaseModel):
    response: str
    confidence: float
    sources: list = []

@app.post("/query", response_model=QueryResponse)
async def query_agent(request: QueryRequest):
    try:
        result = await agent.process_query(request.message)
        return QueryResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    return {"status": "healthy", "agent": "cybersecurity"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
