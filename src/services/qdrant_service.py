from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct
from qdrant_client.http import models
import logging
import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime
import numpy as np
from sentence_transformers import SentenceTransformer

logger = logging.getLogger(__name__)

class QdrantAnomalyService:
    def __init__(self, url: str = "https://qdrant.teapec.com", collection_name: str = "anomalies"):
        self.client = QdrantClient(url=url)
        self.collection_name = collection_name
        self.model = SentenceTransformer('all-MiniLM-L6-v2')  # For text embedding
        self.vector_size = 384  # Dimension of all-MiniLM-L6-v2 embeddings
        self._ensure_collection_exists()
    
    def _ensure_collection_exists(self):
        """Create collection if it doesn't exist"""
        try:
            collections = self.client.get_collections()
            collection_names = [col.name for col in collections.collections]
            
            if self.collection_name not in collection_names:
                logger.info(f"Creating collection: {self.collection_name}")
                self.client.create_collection(
                    collection_name=self.collection_name,
                    vectors_config=VectorParams(
                        size=self.vector_size, 
                        distance=Distance.COSINE
                    ),
                )
                logger.info(f"Collection {self.collection_name} created successfully")
            else:
                logger.info(f"Collection {self.collection_name} already exists")
                
        except Exception as e:
            logger.error(f"Error ensuring collection exists: {e}")
            raise
    
    def _generate_embedding(self, text_data: str) -> List[float]:
        """Generate embedding vector from text data"""
        try:
            embedding = self.model.encode(text_data)
            return embedding.tolist()
        except Exception as e:
            logger.error(f"Error generating embedding: {e}")
            # Return zero vector as fallback
            return [0.0] * self.vector_size
    
    def _prepare_log_text(self, log_data: Dict[Any, Any]) -> str:
        """Convert log data to text for embedding generation"""
        try:
            # Convert log data to a meaningful text representation
            if isinstance(log_data, dict):
                # Extract key fields for better text representation
                important_fields = []
                
                # Common log fields to prioritize
                priority_keys = ['message', 'event_type', 'action', 'user', 'source', 'destination', 
                               'process_name', 'command_line', 'file_path', 'url', 'error']
                
                # Add priority fields first
                for key in priority_keys:
                    if key in log_data and log_data[key]:
                        important_fields.append(f"{key}: {log_data[key]}")
                
                # Add other fields
                for key, value in log_data.items():
                    if key not in priority_keys and value:
                        important_fields.append(f"{key}: {value}")
                
                return " | ".join(important_fields)
            else:
                return str(log_data)
                
        except Exception as e:
            logger.error(f"Error preparing log text: {e}")
            return str(log_data)
    
    def store_anomaly(self, log_id: int, log_data: Dict[Any, Any], anomaly_score: float, 
                     source_ip: str = None, source_type: str = None, timestamp: datetime = None) -> bool:
        """Store anomaly in Qdrant vector database"""
        try:
            # Prepare text for embedding
            log_text = self._prepare_log_text(log_data)
            
            # Generate embedding
            vector = self._generate_embedding(log_text)
            
            # Prepare metadata
            payload = {
                "log_id": log_id,
                "anomaly_score": anomaly_score,
                "source_ip": source_ip,
                "source_type": source_type,
                "timestamp": timestamp.isoformat() if timestamp else datetime.now().isoformat(),
                "log_data": log_data,
                "log_text": log_text,  # Store the text representation for reference
                "indexed_at": datetime.now().isoformat()
            }
            
            # Create point
            point = PointStruct(
                id=log_id,  # Use log_id as the point ID
                vector=vector,
                payload=payload
            )
            
            # Upload to Qdrant
            operation_info = self.client.upsert(
                collection_name=self.collection_name,
                wait=True,
                points=[point]
            )
            
            if operation_info.status == models.UpdateStatus.COMPLETED:
                logger.info(f"Successfully stored anomaly {log_id} in Qdrant")
                return True
            else:
                logger.error(f"Failed to store anomaly {log_id}: {operation_info}")
                return False
                
        except Exception as e:
            logger.error(f"Error storing anomaly {log_id} in Qdrant: {e}")
            return False
    
    def search_similar_anomalies(self, query_text: str, limit: int = 10, 
                                score_threshold: float = 0.7) -> List[Dict]:
        """Search for similar anomalies based on text similarity"""
        try:
            # Generate embedding for query
            query_vector = self._generate_embedding(query_text)
            
            # Search in Qdrant
            search_result = self.client.search(
                collection_name=self.collection_name,
                query_vector=query_vector,
                limit=limit,
                score_threshold=score_threshold,
                with_payload=True
            )
            
            # Format results
            results = []
            for hit in search_result:
                result = {
                    "log_id": hit.id,
                    "similarity_score": hit.score,
                    "anomaly_score": hit.payload.get("anomaly_score"),
                    "source_ip": hit.payload.get("source_ip"),
                    "source_type": hit.payload.get("source_type"),
                    "timestamp": hit.payload.get("timestamp"),
                    "log_text": hit.payload.get("log_text"),
                    "log_data": hit.payload.get("log_data")
                }
                results.append(result)
            
            return results
            
        except Exception as e:
            logger.error(f"Error searching similar anomalies: {e}")
            return []
    
    def get_anomaly_by_log_id(self, log_id: int) -> Optional[Dict]:
        """Retrieve specific anomaly by log ID"""
        try:
            points = self.client.retrieve(
                collection_name=self.collection_name,
                ids=[log_id],
                with_payload=True,
                with_vectors=False
            )
            
            if points:
                point = points[0]
                return {
                    "log_id": point.id,
                    "anomaly_score": point.payload.get("anomaly_score"),
                    "source_ip": point.payload.get("source_ip"),
                    "source_type": point.payload.get("source_type"),
                    "timestamp": point.payload.get("timestamp"),
                    "log_text": point.payload.get("log_text"),
                    "log_data": point.payload.get("log_data"),
                    "indexed_at": point.payload.get("indexed_at")
                }
            return None
            
        except Exception as e:
            logger.error(f"Error retrieving anomaly {log_id}: {e}")
            return None
    
    def get_collection_stats(self) -> Dict:
        """Get collection statistics"""
        try:
            info = self.client.get_collection(self.collection_name)
            return {
                "collection_name": self.collection_name,
                "points_count": info.points_count,
                "vectors_count": info.vectors_count,
                "status": info.status,
                "indexed_vectors_count": info.indexed_vectors_count
            }
        except Exception as e:
            logger.error(f"Error getting collection stats: {e}")
            return {}
    
    def delete_anomaly(self, log_id: int) -> bool:
        """Delete anomaly from vector database"""
        try:
            operation_info = self.client.delete(
                collection_name=self.collection_name,
                points_selector=models.PointIdsList(points=[log_id])
            )
            
            if operation_info.status == models.UpdateStatus.COMPLETED:
                logger.info(f"Successfully deleted anomaly {log_id} from Qdrant")
                return True
            else:
                logger.error(f"Failed to delete anomaly {log_id}: {operation_info}")
                return False
                
        except Exception as e:
            logger.error(f"Error deleting anomaly {log_id}: {e}")
            return False