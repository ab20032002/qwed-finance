# Add this to root of qwed-finance
FROM python:3.11-slim

# Install QWED Finance (Source:)
RUN pip install qwed-finance pandas

# Copy your runner script
COPY action_entrypoint.py /action_entrypoint.py

# Make it executable
RUN chmod +x /action_entrypoint.py

ENTRYPOINT ["python", "/action_entrypoint.py"]
