#!/usr/bin/env python3
"""
Main entry point for the AI-powered IDS/IPS system.
Coordinates all components and manages the system lifecycle.
"""

import asyncio
import logging
import signal
import sys
from pathlib import Path
from typing import Optional

import uvicorn
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.capture.packet_capture import PacketCaptureService
from src.fe.extract import FeatureExtractor
from src.inference.model_server import ModelServer
from src.decision.engine import DecisionEngine
from src.monitoring.metrics import MetricsCollector
from src.utils.config import Config
from src.utils.logger import setup_logging

# Global services
services = {}
config = Config()


def setup_fastapi() -> FastAPI:
    """Setup FastAPI application with all routes and middleware."""
    app = FastAPI(
        title="AI-Powered IDS/IPS",
        description="Intrusion Detection and Prevention System",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc"
    )
    
    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Health check endpoint
    @app.get("/health")
    async def health_check():
        return {
            "status": "healthy",
            "version": "1.0.0",
            "services": {name: "running" for name in services.keys()}
        }
    
    # Metrics endpoint
    @app.get("/metrics")
    async def get_metrics():
        if "metrics" in services:
            return services["metrics"].get_metrics()
        return {"error": "Metrics collector not available"}
    
    return app


async def initialize_services():
    """Initialize all system services."""
    logger = logging.getLogger(__name__)
    
    try:
        # Initialize metrics collector
        logger.info("Initializing metrics collector...")
        services["metrics"] = MetricsCollector()
        await services["metrics"].start()
        
        # Initialize feature extractor
        logger.info("Initializing feature extractor...")
        services["feature_extractor"] = FeatureExtractor()
        await services["feature_extractor"].start()
        
        # Initialize model server
        logger.info("Initializing model server...")
        services["model_server"] = ModelServer()
        await services["model_server"].start()
        
        # Initialize decision engine
        logger.info("Initializing decision engine...")
        services["decision_engine"] = DecisionEngine()
        await services["decision_engine"].start()
        
        # Initialize packet capture
        logger.info("Initializing packet capture service...")
        services["packet_capture"] = PacketCaptureService()
        await services["packet_capture"].start()
        
        logger.info("All services initialized successfully!")
        
    except Exception as e:
        logger.error(f"Failed to initialize services: {e}")
        raise


async def shutdown_services():
    """Gracefully shutdown all services."""
    logger = logging.getLogger(__name__)
    
    for name, service in services.items():
        try:
            logger.info(f"Shutting down {name}...")
            if hasattr(service, 'stop'):
                await service.stop()
        except Exception as e:
            logger.error(f"Error shutting down {name}: {e}")


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger = logging.getLogger(__name__)
    logger.info(f"Received signal {signum}, initiating shutdown...")
    
    # Create new event loop for shutdown
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(shutdown_services())
    loop.close()
    
    sys.exit(0)


async def main():
    """Main application entry point."""
    # Setup logging
    setup_logging()
    logger = logging.getLogger(__name__)
    
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    try:
        logger.info("Starting AI-powered IDS/IPS system...")
        
        # Initialize services
        await initialize_services()
        
        # Start FastAPI server
        app = setup_fastapi()
        
        # Start the server
        config_uvicorn = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=8000,
            log_level="info",
            access_log=True
        )
        server = uvicorn.Server(config_uvicorn)
        
        logger.info("System started successfully!")
        logger.info("API documentation available at: http://localhost:8000/docs")
        logger.info("Health check available at: http://localhost:8000/health")
        
        # Run the server
        await server.serve()
        
    except KeyboardInterrupt:
        logger.info("Received keyboard interrupt, shutting down...")
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        raise
    finally:
        await shutdown_services()
        logger.info("System shutdown complete.")


if __name__ == "__main__":
    asyncio.run(main())
