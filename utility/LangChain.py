from dotenv import load_dotenv
load_dotenv()

from langchain.chat_models import init_chat_model
from langgraph.graph import START, StateGraph
from langchain_core.prompts import PromptTemplate
from typing_extensions import List, TypedDict

# Initialize the LLM
model = init_chat_model("gpt-4o", model_provider="openai")

# Create a prompt
template = """Use the following pieces of context to answer the question at the end.
If you don't know the answer, just say that you don't know, don't try to make up an answer.

{context}

Question: {question}

Answer:"""

prompt = PromptTemplate.from_template(template)

# Define state for application
class State(TypedDict):
    question: str
    context: List[dict]
    answer: str

# Define functions for each step in the application

# Retrieve context 
def retrieve(state: State):
    context = [
        {"location": "London", "weather": "Cloudy, sunny skies later"},
        {"location": "San Francisco", "weather": "Sunny skies, raining overnight."},
    ]
    return {"context": context}

# Generate the answer based on the question and context
def generate(state: State):
    messages = prompt.invoke({"question": state["question"], "context": state["context"]})
    response = model.invoke(messages)
    return {"answer": response.content}

# Define application steps
workflow = StateGraph(State).add_sequence([retrieve, generate])
workflow.add_edge(START, "retrieve")
app = workflow.compile()

# Run the application
question = "What is the weather in San Francisco?"
response = app.invoke({"question": question})
print("Answer:", response["answer"])


#=================================================
genai-integration-langchain/neo4j_query.py

import os
from dotenv import load_dotenv
load_dotenv()

from langchain_neo4j import Neo4jGraph

# Create Neo4jGraph instance
graph = Neo4jGraph(
    url=os.getenv("NEO4J_URI"),
    username=os.getenv("NEO4J_USERNAME"),
    password=os.getenv("NEO4J_PASSWORD"),
    database=os.getenv("NEO4J_DATABASE"),
)

#You can use data returned from queries as context for an agent.
# Run a query and print the result
result = graph.query("""
MATCH (m:Movie {title: "Mission: Impossible"})<-[a:ACTED_IN]-(p:Person)
RETURN p.name AS actor, a.role AS role
""")

print(result


#==================================
You can view the database schema using the Cypher query:
CALL db.schema.visualization()    