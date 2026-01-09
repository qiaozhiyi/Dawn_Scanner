"""
Dawn Scanner - LLM Service
This module uses LangChain with Tongyi Qwen to generate detailed vulnerability reports
"""

import os
import logging
from datetime import datetime
from typing import Dict, List, Any
from pydantic import BaseModel, Field
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import LangChain components for Tongyi Qwen
from langchain_community.chat_models.tongyi import ChatTongyi
from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import StrOutputParser
from langchain_core.pydantic_v1 import BaseModel as LangChainBaseModel


# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="Dawn Scanner LLM Service",
    description="LLM-powered vulnerability report generation service with Tongyi Qwen",
    version="1.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Data models
class Vulnerability(BaseModel):
    id: str
    type: str
    severity: str
    description: str
    url: str
    details: str


class ScanReportRequest(BaseModel):
    task_id: str
    url: str
    vulnerabilities: List[Vulnerability]
    summary: str


class ScanReportResponse(BaseModel):
    task_id: str
    report: str
    status: str
    error: str = None


class ReportChain:
    """LangChain-based report generation chain with Tongyi Qwen"""

    def __init__(self):
        # Initialize the LLM with Tongyi Qwen
        api_key = os.getenv("DASHSCOPE_API_KEY")
        if not api_key:
            raise ValueError("DASHSCOPE_API_KEY is not set")
        model_name = os.getenv("LLM_MODEL_NAME", "qwen-max")  # Using qwen-max for detailed reports

        self.llm = ChatTongyi(
            model_name=model_name,
            dashscope_api_key=api_key,
            temperature=0.3
        )

        # Create the prompt template for vulnerability report generation
        self.prompt = ChatPromptTemplate.from_messages([
            ("system", "你是一位专业的网络安全分析师。请基于提供的漏洞扫描结果生成一份详细的专业安全报告。报告应结构清晰、可操作，并包含修复建议。"),
            ("human", """
            目标URL: {url}

            扫描摘要: {summary}

            发现的漏洞:
            {vulnerabilities_text}

            请生成一份全面的安全报告，包含以下内容:
            1. 执行摘要
            2. 详细漏洞分析
            3. 风险评估
            4. 推荐的修复步骤
            5. 预防措施
            """)
        ])

        # Create the chain
        self.chain = self.prompt | self.llm | StrOutputParser()

    def format_vulnerabilities(self, vulnerabilities: List[Vulnerability]) -> str:
        """Format vulnerabilities into a readable text format for the LLM"""
        formatted = []
        for i, vuln in enumerate(vulnerabilities, 1):
            formatted.append(
                f"{i}. {vuln.type} (严重程度: {vuln.severity})\n"
                f"   描述: {vuln.description}\n"
                f"   详情: {vuln.details}\n"
                f"   URL: {vuln.url}\n"
            )
        return "\n".join(formatted)

    def generate_report(self, request: ScanReportRequest) -> str:
        """Generate a detailed security report using LangChain with Tongyi Qwen"""
        try:
            # Format vulnerabilities for the prompt
            vulnerabilities_text = self.format_vulnerabilities(request.vulnerabilities)

            # Prepare the input for the chain
            input_data = {
                "url": request.url,
                "summary": request.summary,
                "vulnerabilities_text": vulnerabilities_text
            }

            # Generate the report
            report = self.chain.invoke(input_data)

            return report

        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            raise


# Initialize the report chain
report_chain = ReportChain()


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "ok", "service": "dawn-scanner-llm-service-qwen"}


@app.post("/api/report/generate", response_model=ScanReportResponse)
async def generate_report(request: ScanReportRequest):
    """Generate a detailed security report using Tongyi Qwen LLM"""
    try:
        logger.info(f"Generating report for task {request.task_id}")

        # Generate the report using LangChain with Tongyi Qwen
        report_content = report_chain.generate_report(request)

        response = ScanReportResponse(
            task_id=request.task_id,
            report=report_content,
            status="completed"
        )

        logger.info(f"Report generated successfully for task {request.task_id}")
        return response

    except Exception as e:
        logger.error(f"Error generating report for task {request.task_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to generate report: {str(e)}"
        )


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "Dawn Scanner LLM Service with Tongyi Qwen",
        "endpoints": {
            "health": "/health",
            "generate_report": "/api/report/generate (POST)"
        }
    }


if __name__ == "__main__":
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app:app", host="0.0.0.0", port=port, reload=True)
