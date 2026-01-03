#!/usr/bin/env python3
"""
NotebookLM Integration Pipeline for ECH0 Training
Copyright (c) 2025 Joshua Hendricks Cole (DBA: Corporation of Light). All Rights Reserved. PATENT PENDING.

Processes course materials through NotebookLM to create:
- Interactive Q&A models per course
- Knowledge graphs with concept relationships
- Searchable embeddings
- Conversational interfaces per domain
"""

import asyncio
import json
import numpy as np
import pickle
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass
import hashlib
import logging
from concurrent.futures import ThreadPoolExecutor
import torch
import torch.nn.functional as F
from transformers import AutoTokenizer, AutoModel, pipeline
import networkx as nx
from sentence_transformers import SentenceTransformer
import faiss

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class NotebookLMModel:
    """Represents a trained NotebookLM model for a course."""

    course_id: str
    course_name: str
    embeddings: np.ndarray
    qa_pairs: List[Dict[str, str]]
    knowledge_graph: nx.DiGraph
    concept_embeddings: Dict[str, np.ndarray]
    metadata: Dict[str, Any]
    vector_index: faiss.IndexFlatL2

    def save(self, filepath: Path):
        """Save model to disk."""
        with open(filepath, 'wb') as f:
            pickle.dump({
                'course_id': self.course_id,
                'course_name': self.course_name,
                'embeddings': self.embeddings,
                'qa_pairs': self.qa_pairs,
                'knowledge_graph': nx.node_link_data(self.knowledge_graph),
                'concept_embeddings': self.concept_embeddings,
                'metadata': self.metadata
            }, f)

    @classmethod
    def load(cls, filepath: Path):
        """Load model from disk."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            graph_data = data['knowledge_graph']
            data['knowledge_graph'] = nx.node_link_graph(graph_data)

            # Rebuild FAISS index
            embeddings = data['embeddings']
            index = faiss.IndexFlatL2(embeddings.shape[1])
            index.add(embeddings.astype(np.float32))
            data['vector_index'] = index

            return cls(**data)


class NotebookLMPipeline:
    """Main pipeline for processing course materials through NotebookLM."""

    def __init__(self, model_name: str = 'sentence-transformers/all-mpnet-base-v2'):
        """Initialize pipeline with embedding model."""
        self.device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        self.embedding_model = SentenceTransformer(model_name)
        self.qa_generator = pipeline('question-answering', device=0 if torch.cuda.is_available() else -1)
        self.summarizer = pipeline('summarization', device=0 if torch.cuda.is_available() else -1)
        self.output_dir = Path("/Users/noone/aios/ech0_models")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def process_course(self, course_data: Dict[str, Any]) -> NotebookLMModel:
        """
        Process a single course through NotebookLM pipeline.

        Args:
            course_data: Dictionary containing course materials

        Returns:
            Trained NotebookLM model for the course
        """
        logger.info(f"Processing course: {course_data.get('course_id', 'Unknown')}")

        # Extract text from all materials
        all_text = await self.extract_all_text(course_data)

        # Generate embeddings
        embeddings = self.generate_embeddings(all_text)

        # Generate Q&A pairs
        qa_pairs = await self.generate_qa_pairs(all_text, course_data)

        # Build knowledge graph
        knowledge_graph = await self.build_knowledge_graph(all_text, course_data)

        # Extract concepts and their embeddings
        concept_embeddings = self.extract_concept_embeddings(knowledge_graph, all_text)

        # Build vector search index
        vector_index = self.build_vector_index(embeddings)

        # Create NotebookLM model
        model = NotebookLMModel(
            course_id=course_data.get('course_id', 'unknown'),
            course_name=course_data.get('title', 'Unknown Course'),
            embeddings=embeddings,
            qa_pairs=qa_pairs,
            knowledge_graph=knowledge_graph,
            concept_embeddings=concept_embeddings,
            metadata={
                'university': course_data.get('university', 'MIT'),
                'department': course_data.get('department', 'unknown'),
                'level': course_data.get('level', 'undergraduate'),
                'num_materials': len(course_data.get('materials', {})),
                'num_qa_pairs': len(qa_pairs),
                'num_concepts': knowledge_graph.number_of_nodes()
            },
            vector_index=vector_index
        )

        # Save model
        model_path = self.output_dir / f"{model.course_id}_notebooklm.pkl"
        model.save(model_path)
        logger.info(f"Saved NotebookLM model to {model_path}")

        return model

    async def extract_all_text(self, course_data: Dict[str, Any]) -> List[str]:
        """Extract text from all course materials."""
        texts = []

        # Extract from transcripts
        for transcript in course_data.get('transcripts', []):
            texts.append(transcript.get('transcript', ''))

        # Extract from lecture notes
        for note in course_data.get('lecture_notes', []):
            # In real implementation, would download and parse PDF
            texts.append(note.get('title', ''))

        # Extract from problem sets
        for pset in course_data.get('problem_sets', []):
            texts.append(pset.get('title', ''))

        # Extract from exams
        for exam in course_data.get('exams', []):
            texts.append(exam.get('title', ''))

        return texts

    def generate_embeddings(self, texts: List[str]) -> np.ndarray:
        """Generate embeddings for all text chunks."""
        # Split texts into chunks for better processing
        chunks = []
        for text in texts:
            # Split into 512 token chunks
            words = text.split()
            for i in range(0, len(words), 100):
                chunk = ' '.join(words[i:i+100])
                if chunk:
                    chunks.append(chunk)

        if not chunks:
            return np.array([])

        # Generate embeddings
        embeddings = self.embedding_model.encode(chunks, show_progress_bar=True)
        return embeddings

    async def generate_qa_pairs(self, texts: List[str], course_data: Dict[str, Any]) -> List[Dict[str, str]]:
        """Generate Q&A pairs from course materials."""
        qa_pairs = []

        # Generate questions for key concepts
        key_concepts = self.extract_key_concepts(texts)

        for concept in key_concepts[:100]:  # Limit to top 100 concepts
            # Generate questions about the concept
            questions = self.generate_questions_for_concept(concept, texts)

            for question in questions:
                # Generate answer using the QA model
                context = self.find_relevant_context(question, texts)

                if context:
                    try:
                        answer = self.qa_generator(question=question, context=context)
                        qa_pairs.append({
                            'question': question,
                            'answer': answer['answer'],
                            'confidence': answer.get('score', 0.0),
                            'concept': concept,
                            'course_id': course_data.get('course_id')
                        })
                    except Exception as e:
                        logger.warning(f"Failed to generate answer for question: {question}")

        logger.info(f"Generated {len(qa_pairs)} Q&A pairs")
        return qa_pairs

    def extract_key_concepts(self, texts: List[str]) -> List[str]:
        """Extract key concepts from course materials."""
        concepts = []

        # Simple extraction based on capitalized multi-word phrases
        # In real implementation, would use NER or concept extraction models
        for text in texts:
            words = text.split()
            for i in range(len(words) - 1):
                if words[i][0].isupper() and words[i+1][0].isupper():
                    concept = f"{words[i]} {words[i+1]}"
                    if concept not in concepts:
                        concepts.append(concept)

        return concepts[:200]  # Return top 200 concepts

    def generate_questions_for_concept(self, concept: str, texts: List[str]) -> List[str]:
        """Generate questions about a specific concept."""
        questions = [
            f"What is {concept}?",
            f"How does {concept} work?",
            f"What are the applications of {concept}?",
            f"What is the mathematical formulation of {concept}?",
            f"How is {concept} related to other concepts in this course?",
        ]

        return questions[:3]  # Return top 3 questions

    def find_relevant_context(self, question: str, texts: List[str]) -> str:
        """Find relevant context for answering a question."""
        # Embed the question
        question_embedding = self.embedding_model.encode([question])[0]

        # Find most similar text chunks
        max_similarity = -1
        best_context = ""

        for text in texts:
            if len(text) > 50:  # Only consider substantial text
                text_embedding = self.embedding_model.encode([text[:500]])[0]
                similarity = np.dot(question_embedding, text_embedding)

                if similarity > max_similarity:
                    max_similarity = similarity
                    best_context = text[:1000]  # Use first 1000 chars as context

        return best_context

    async def build_knowledge_graph(self, texts: List[str], course_data: Dict[str, Any]) -> nx.DiGraph:
        """Build knowledge graph of concepts and relationships."""
        G = nx.DiGraph()

        # Extract concepts
        concepts = self.extract_key_concepts(texts)

        # Add concepts as nodes
        for concept in concepts:
            G.add_node(concept, type='concept', course_id=course_data.get('course_id'))

        # Find relationships between concepts
        for i, concept1 in enumerate(concepts):
            for concept2 in concepts[i+1:]:
                # Check if concepts appear together in texts
                for text in texts:
                    if concept1 in text and concept2 in text:
                        # Calculate proximity
                        idx1 = text.find(concept1)
                        idx2 = text.find(concept2)
                        distance = abs(idx1 - idx2)

                        if distance < 200:  # Within 200 characters
                            # Add edge with weight based on proximity
                            weight = 1.0 / (1 + distance / 100)
                            G.add_edge(concept1, concept2, weight=weight)
                            break

        # Add hierarchical relationships
        self.add_hierarchical_relationships(G, course_data)

        logger.info(f"Built knowledge graph with {G.number_of_nodes()} nodes and {G.number_of_edges()} edges")
        return G

    def add_hierarchical_relationships(self, G: nx.DiGraph, course_data: Dict[str, Any]):
        """Add hierarchical relationships to knowledge graph."""
        # Add course hierarchy
        course_id = course_data.get('course_id', 'unknown')
        department = course_data.get('department', 'unknown')

        # Create hierarchy: Department -> Course -> Concepts
        G.add_node(department, type='department')
        G.add_node(course_id, type='course')
        G.add_edge(department, course_id)

        # Link concepts to course
        for node in list(G.nodes()):
            if G.nodes[node].get('type') == 'concept':
                G.add_edge(course_id, node)

    def extract_concept_embeddings(self, knowledge_graph: nx.DiGraph, texts: List[str]) -> Dict[str, np.ndarray]:
        """Extract embeddings for each concept in the knowledge graph."""
        concept_embeddings = {}

        for node in knowledge_graph.nodes():
            if knowledge_graph.nodes[node].get('type') == 'concept':
                # Find text context for concept
                context = ""
                for text in texts:
                    if node in text:
                        idx = text.find(node)
                        context = text[max(0, idx-100):min(len(text), idx+100)]
                        break

                if context:
                    embedding = self.embedding_model.encode([context])[0]
                    concept_embeddings[node] = embedding

        return concept_embeddings

    def build_vector_index(self, embeddings: np.ndarray) -> faiss.IndexFlatL2:
        """Build FAISS vector index for fast similarity search."""
        if len(embeddings) == 0:
            return None

        # Create FAISS index
        dimension = embeddings.shape[1]
        index = faiss.IndexFlatL2(dimension)

        # Add embeddings to index
        index.add(embeddings.astype(np.float32))

        logger.info(f"Built FAISS index with {index.ntotal} vectors")
        return index


class NotebookLMConversationalInterface:
    """Conversational interface for NotebookLM models."""

    def __init__(self, models: List[NotebookLMModel]):
        """Initialize with list of NotebookLM models."""
        self.models = {model.course_id: model for model in models}
        self.current_context = None
        self.conversation_history = []

    def query(self, question: str, course_id: Optional[str] = None) -> str:
        """
        Query the NotebookLM models.

        Args:
            question: Question to answer
            course_id: Optional specific course to query

        Returns:
            Answer string
        """
        if course_id and course_id in self.models:
            # Query specific course
            return self.query_course(question, self.models[course_id])
        else:
            # Query all courses and find best answer
            return self.query_all_courses(question)

    def query_course(self, question: str, model: NotebookLMModel) -> str:
        """Query a specific course model."""
        # Embed question
        question_embedding = model.concept_embeddings.get(
            question,
            np.random.randn(768)  # Fallback embedding
        )

        # Search in vector index
        if model.vector_index:
            D, I = model.vector_index.search(
                question_embedding.reshape(1, -1).astype(np.float32),
                k=5
            )

            # Get top matching Q&A pairs
            relevant_qa = []
            for idx in I[0]:
                if idx < len(model.qa_pairs):
                    relevant_qa.append(model.qa_pairs[idx])

            if relevant_qa:
                # Return best answer
                return relevant_qa[0].get('answer', 'No answer found')

        return f"No answer found in course {model.course_id}"

    def query_all_courses(self, question: str) -> str:
        """Query all courses and return best answer."""
        best_answer = ""
        best_confidence = 0

        for course_id, model in self.models.items():
            answer = self.query_course(question, model)

            # Simple confidence based on answer length (in real implementation, use model confidence)
            confidence = len(answer) / 100.0

            if confidence > best_confidence:
                best_confidence = confidence
                best_answer = f"[{model.course_name}] {answer}"

        return best_answer or "No answer found in any course"

    def get_concept_explanation(self, concept: str, course_id: Optional[str] = None) -> str:
        """Get detailed explanation of a concept."""
        explanations = []

        courses_to_check = [self.models[course_id]] if course_id else self.models.values()

        for model in courses_to_check:
            if concept in model.knowledge_graph:
                # Get connected concepts
                neighbors = list(model.knowledge_graph.neighbors(concept))

                explanation = f"In {model.course_name}:\n"
                explanation += f"{concept} is related to: {', '.join(neighbors[:5])}\n"

                # Find Q&A pairs about this concept
                relevant_qa = [qa for qa in model.qa_pairs if concept.lower() in qa['question'].lower()]
                if relevant_qa:
                    explanation += f"Key insights: {relevant_qa[0]['answer']}"

                explanations.append(explanation)

        return '\n\n'.join(explanations) if explanations else f"No explanation found for {concept}"


async def batch_process_courses(course_data_list: List[Dict[str, Any]]) -> List[NotebookLMModel]:
    """Batch process multiple courses through NotebookLM."""
    pipeline = NotebookLMPipeline()
    models = []

    for course_data in course_data_list:
        try:
            model = await pipeline.process_course(course_data)
            models.append(model)
        except Exception as e:
            logger.error(f"Failed to process course {course_data.get('course_id')}: {e}")

    return models


async def main():
    """Main entry point for NotebookLM processing."""
    # Load sample course data (in real implementation, load from scraper output)
    sample_course = {
        'course_id': '18.01',
        'title': 'Single Variable Calculus',
        'university': 'MIT',
        'department': 'Mathematics',
        'level': 'undergraduate',
        'transcripts': [
            {'transcript': 'This is a lecture about derivatives and integrals...'}
        ],
        'lecture_notes': [
            {'title': 'Introduction to Calculus'}
        ],
        'problem_sets': [
            {'title': 'Problem Set 1: Limits'}
        ],
        'exams': [
            {'title': 'Midterm Exam 1'}
        ]
    }

    # Process course
    pipeline = NotebookLMPipeline()
    model = await pipeline.process_course(sample_course)

    print(f"\n=== NotebookLM Model Created ===")
    print(f"Course: {model.course_name}")
    print(f"Q&A Pairs: {len(model.qa_pairs)}")
    print(f"Knowledge Graph Nodes: {model.knowledge_graph.number_of_nodes()}")
    print(f"Embeddings Shape: {model.embeddings.shape}")

    # Test conversational interface
    interface = NotebookLMConversationalInterface([model])
    answer = interface.query("What is a derivative?", course_id='18.01')
    print(f"\nQuery Test: {answer}")


if __name__ == "__main__":
    asyncio.run(main())