# Start with a minimal Alpine-based Python image
FROM python:3.12-alpine

# Set environment variables for Python to avoid buffering and write logs immediately
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set the working directory inside the container
WORKDIR /app

# Copy only the required files into the container
COPY main.py ./
COPY pfsense.py ./
COPY requirements.txt ./

# Install required python packages
RUN pip install --no-cache-dir -r requirements.txt

# Default command to run the script
CMD ["python", "main.py"]
