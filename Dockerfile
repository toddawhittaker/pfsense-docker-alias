# Start with a minimal Alpine-based Python image
FROM python:3.14-alpine

# Set environment variables for Python to avoid buffering and write logs immediately
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# Set the working directory inside the container
WORKDIR /app

# Copy only the required files into the container
COPY main.py ./
COPY pfsense.py ./
COPY requirements.txt ./

# Install required python packages, then remove pip itself.
#
# Nothing at runtime invokes pip -- the container runs `python main.py` -- and
# pip carries a vendored dependency manifest (pip/_vendor/vendor.txt and
# bom.cdx.json) that image scanners read. Trivy reported HIGH findings there for
# a vendored msgpack and for setuptools, which is not even installed in this
# image, only listed in that manifest. Neither is reachable at runtime.
#
# Removing the installer drops those findings at their source rather than
# suppressing them, and takes a package installer out of a container that mounts
# the Docker socket. Re-adding pip re-adds the findings.
RUN pip install --no-cache-dir -r requirements.txt \
    && python -m pip uninstall -y pip

# Default command to run the script
CMD ["python", "main.py"]
