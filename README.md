# 📡 pfSense Docker Alias

## Overview

The **pfSense Docker Alias** project is a lightweight Python-based container that dynamically updates DNS aliases in pfSense based on Docker container events. 🐳 It listens for Docker container start/stop events, extracts relevant labels from the container configuration, and updates the DNS host overrides in pfSense.

This container is perfect for dynamic environments where services are deployed using Docker and a reverse proxy. It ensures your services are always accessible via DNS without manual intervention! 🚀

## Why Use This? 🤔

Managing DNS entries for services running in Docker can be a pain, especially in environments where services frequently change. This project simplifies the process by:
- ✅ Automatically adding DNS aliases to a specified host override in pfSense when containers start.
- ❌ Optionally removing aliases when containers stop.
- 🔄 Optionally syncing aliases for all existing containers on startup.

By leveraging the unofficial [pfSense REST API](https://pfrest.org/), this container ensures DNS records stay in sync with your Docker services.

## How It Works ⚙️

Without this tool, a typical deployment workflow involves:
1. **Starting Your Docker Container**:
   - Example:
     ```bash
     docker run -d --name my-service -p 8080:80 my-service-image
     ```

2. **Configuring Your Reverse Proxy**:
   - Example Caddyfile:
     ```caddyfile
     my-service.lab.internal {
         reverse_proxy docker.lab.internal:8080
     }
     ```

3. **Updating Your DNS Resolver**:
   - Manually add an alias entry for `my-service.yourdomain.com` pointing to your reverse proxy in pfSense.

With **pfSense Docker Alias**, the **last step** is automated! Simply label your Docker containers, and the app updates your DNS configuration in pfSense.

## Features ✨

- **Dynamic DNS Alias Management**: Automatically add and remove DNS aliases for Docker containers.
- **Startup Alias Sync**: Optionally scans all existing containers and ensures aliases are present in pfSense.
- **Highly Configurable**: Flexible environment variables and Docker labels.
- **Lightweight**: Built on an Alpine-based Python image for minimal resource usage.
- **Secure**: Requires API key-based authentication for pfSense.
- **Flexible**: Works with self-signed certificates for pfSense.

## Requirements 🛠️

- A running pfSense instance.
- The unoffical [pfSense REST API](https://pfrest.org/) manually installed on pfSense.  
  Follow the installation instructions here: [Install and Configure the API](https://pfrest.org/INSTALL_AND_CONFIG/)
- An API key for the pfSense REST API.  
  Generate an API key by following:  [Authentication and Authorization](https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/)

## Installation Guide 🚀

### Using the pre-built image
Do you trust me? Okay, feel free to use the pre-built image that I'm running in my lab.

#### Using `docker compose`
1. **Pull the Pre-Built Image**:
   - Use Docker to pull the image directly from `ghcr.io`:
     ```bash
     docker pull ghcr.io/toddawhittaker/pfsense-docker-alias:latest
     ```

2. **Prepare `docker-compose.yaml`**:
   - Create or modify a `docker-compose.yaml` file for your setup. Here’s an example:
     ```yaml
     services:
       pfsense-docker-alias:
         image: ghcr.io/toddawhittaker/pfsense-docker-alias:latest
         container_name: pfsense-docker-alias
         environment:
           PFSENSE_HOSTNAME: "pfsense.lab.internal"
           PFSENSE_API_TOKEN: "your_secure_api_token"
           # Uncomment to enable scanning for aliases on startup
           # ADD_ALIASES_ON_STARTUP: "true"
         volumes:
           - /var/run/docker.sock:/var/run/docker.sock
         restart: unless-stopped
     ```

3. **Start the Service**:
   - Run the following command to start the container:
     ```bash
     docker-compose up -d
     ```

4. **Verify Logs**:
   - Check the logs to confirm the container is running and communicating with pfSense:
     ```bash
     docker-compose logs -f
     ```

5. **Stop the Service** (Optional):
   - If you need to stop the container:
     ```bash
     docker-compose down
     ```
#### Using `docker run`
```bash
docker run \
  --name pfsense-docker-alias \
  -e PFSENSE_HOSTNAME="pfsense.lab.internal" \
  -e PFSENSE_API_TOKEN="your_secure_api_token" \
  -e ADD_ALIASES_ON_STARTUP="false" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/toddawhittaker/pfsense-docker-alias:latest
```

### Notes 📝

- Ensure the required environment variables (`PFSENSE_HOSTNAME`, `PFSENSE_API_TOKEN`) are correctly set in your `docker-compose.yaml` file.
- If using `ADD_ALIASES_ON_STARTUP`, ensure all existing containers are labeled correctly before starting the service.
- Replace `pfsense.lab.internal` with the fully qualified hostname or IP address of your pfSense firewall.


### Or Build it Yourself 🚀
Don't trust my image? Check out the git repo, inspect the source, and build it yourself.

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/toddawhittaker/pfsense-docker-alias.git
   cd pfsense-docker-alias
   ```

2. **Build the Docker Image**:
   ```bash
   docker build -t pfsense-docker-alias .
   ```

3. **Configure `docker-compose.yaml`**:
   Use the example provided in the repo or given above to set up your environment variables.

4. **Start the Service**:
   ```bash
   docker-compose up -d
   ```

5. **Check Logs**:
   Verify the service is running correctly:
   ```bash
   docker-compose logs -f
   ```

## Configuration 🔧

### Environment Variables
Use these environment variables in your `docker-compose.yaml` or `docker run` command to configure `pfsense-docker-alias` with details on your infrastructure.

| Variable Name            | Required | Default | Description                                           |
|--------------------------|----------|---------|-------------------------------------------------------|
| `PFSENSE_HOSTNAME`       | Yes      | None    | Fully qualified domain name of your pfSense instance. |
| `PFSENSE_API_TOKEN`      | Yes      | None    | API token for authenticating with pfSense.            |
| `ADD_ALIASES_ON_STARTUP` | No       | `false` | Enable scanning for aliases on startup.               |

### Docker Labels
Use these labels on your services to automatically generate aliases in pfSense DNS.

| Label Name                   | Required | Description                                                           |
|------------------------------|----------|-----------------------------------------------------------------------|
| `pfsense.dns.override`       | Yes      | The **existing** DNS host override in pfSense to associate the alias. |
| `pfsense.dns.alias`          | Yes      | The DNS alias to add for this container.                              |
| `pfsense.dns.remove_on_stop` | No       | Remove the alias when the container stops.                            |
| `pfsense.dns.description`    | No       | Description for the alias                                             |

## Example `docker-compose.yaml` configuring an NGINX web server 🐳
The following example demonstrates how to use the labels for automatically creating aliases. Note that the host override must currently exist in pfSense.

```yaml
services:
  nginx:
    container_name: nginx
    image: nginx:latest
    restart: unless-stopped
    ports:
      - 8080:80
    labels:
      - "pfsense.dns.override=caddy.lab.internal"
      - "pfsense.dns.alias=nginx.lab.internal"
      - "pfsense.dns.description=My nginx websever"
      - "pfsense.dns.remove_on_stop=true"
```
### Notes 📝

- Replace `caddy.lab.internal` with the fully qualified hostname of your reverse proxy. Make sure it exists as a host override in pfSense.
- Replace `nginx.lab.internal` with the fully qualified hostname of the service you're deploying.

## Contributing 💻

Contributions are welcome! Submit issues or pull requests on GitHub to help improve this project.

## License 📜

This project is licensed under the MIT License. See the LICENSE file for details.