from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections and broadcasts messages to all clients."""

    def __init__(self):
        self.active_connections: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        """Accept and register a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.add(websocket)
        logger.info(
            "New WebSocket connection established. "
            f"Active connections: {len(self.active_connections)}"
        )

    def disconnect(self, websocket: WebSocket):
        """Remove a WebSocket connection from the active set."""
        self.active_connections.discard(websocket)
        logger.info(
            "WebSocket connection closed. "
            f"Active connections: {len(self.active_connections)}"
        )

    async def broadcast(self, message: dict):
        """Broadcast a message to all active WebSocket connections.

        Handles disconnected clients gracefully by catching exceptions
        and removing dead connections from the active set.
        """
        dead_connections = set()
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.warning(f"Failed to send message to client: {e}")
                dead_connections.add(connection)

        # Remove any dead connections discovered during broadcast
        for connection in dead_connections:
            self.active_connections.discard(connection)
            logger.info(
                "Removed dead connection. "
                f"Active connections: {len(self.active_connections)}"
            )


manager = ConnectionManager()


@router.websocket("/ws/analysis-feed")
async def analysis_feed(websocket: WebSocket):
    """WebSocket endpoint that provides real-time analysis status updates.

    Clients connect to this endpoint to receive live notifications about
    analysis progress, new submissions, and report availability.
    """
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "connected",
            "message": "Connected to analysis feed",
        })
        while True:
            # Keep the connection alive by waiting for incoming messages.
            # This also allows the client to send messages if needed.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        logger.info("Client disconnected from analysis feed.")


async def notify_analysis_update(
    submission_id: str, status: str, details: dict = None
):
    """Broadcast an analysis status update to all connected clients.

    Args:
        submission_id: The unique identifier of the submission being analyzed.
        status: The current status of the analysis (e.g. "in_progress", "completed").
        details: Optional dictionary with additional details about the update.
    """
    message = {
        "type": "analysis_update",
        "submission_id": submission_id,
        "status": status,
        "details": details,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(message)
    logger.info(
        f"Broadcast analysis update for submission {submission_id}: {status}"
    )


async def notify_new_submission(
    submission_id: str, submission_type: str, filename: str = None
):
    """Broadcast a new submission notification to all connected clients.

    Args:
        submission_id: The unique identifier of the new submission.
        submission_type: The type of submission (e.g. "file", "url", "hash").
        filename: Optional original filename of the submitted sample.
    """
    message = {
        "type": "new_submission",
        "submission_id": submission_id,
        "submission_type": submission_type,
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(message)
    logger.info(
        f"Broadcast new submission notification: {submission_id} "
        f"(type={submission_type})"
    )


async def notify_report_ready(submission_id: str, report_format: str):
    """Broadcast a report-ready notification to all connected clients.

    Args:
        submission_id: The unique identifier of the submission whose report is ready.
        report_format: The format of the generated report (e.g. "pdf", "json", "html").
    """
    message = {
        "type": "report_ready",
        "submission_id": submission_id,
        "format": report_format,
        "timestamp": datetime.utcnow().isoformat(),
    }
    await manager.broadcast(message)
    logger.info(
        f"Broadcast report ready for submission {submission_id} "
        f"(format={report_format})"
    )
