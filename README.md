# 📡 pfSense Docker Alias

## Overview

The **pfSense Docker Alias** project is a lightweight Python-based container that dynamically updates DNS aliases in pfSense based on Docker container events. 🐳 It listens for Docker container start/stop events, extracts relevant labels from the container configuration, and updates the DNS host overrides in pfSense.

This container is perfect for dynamic environments where services are deployed using Docker and a reverse proxy. It ensures your services are always accessible via DNS without manual intervention! 🚀

## Why Use This? 🤔

Managing DNS entries for services running in Docker can be a pain, especially in environments where services frequently change. This project simplifies the process by:
- ✅ Automatically adding DNS aliases to a specified host override in pfSense when containers start.
- ❌ Optionally removing aliases when containers stop or exit.
- 🔄 Optionally adding aliases for currently running containers on startup.

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
- **Startup Alias Sync**: Optionally scans currently running containers and ensures aliases are present in pfSense.
- **Highly Configurable**: Flexible environment variables and Docker labels.
- **Lightweight**: Built on an Alpine-based Python image for minimal resource usage.
- **Secure**: Requires API key-based authentication for pfSense, and verifies the pfSense certificate by default.
- **Flexible**: Works with self-signed certificates for pfSense — mount your CA bundle and set `PFSENSE_CA_BUNDLE`, or turn verification off with `PFSENSE_VERIFY_SSL=false` if you cannot.

## Requirements 🛠️

- A running pfSense instance.
- The unoffical [pfSense REST API](https://pfrest.org/) manually installed on pfSense.  
  Follow the installation instructions here: [Install and Configure the API](https://pfrest.org/INSTALL_AND_CONFIG/)
- An API key for the pfSense REST API.  
  Generate an API key by following:  [Authentication and Authorization](https://pfrest.org/AUTHENTICATION_AND_AUTHORIZATION/)

## Upgrading from v0.1.x ⬆️

**v0.2.0 verifies the pfSense TLS certificate by default.** v0.1.2 and earlier disabled verification on every request, with no way to turn it on. Most pfSense installations use a self-signed certificate, so if yours does, every API call will fail after upgrading until you do one of two things.

Note that this reaches you automatically if you pull the `latest` tag.

The failure is not silent — the service logs the cause and then names both settings:

```
ERROR - API call failed during 'get_all_host_overrides': ... certificate verify failed: self-signed certificate
ERROR - TLS certificate verification failed. Mount a CA bundle and set PFSENSE_CA_BUNDLE
        to its path inside the container, or set PFSENSE_VERIFY_SSL=false to skip
        verification entirely, which exposes the API token to anyone able to intercept
        the connection.
```

**Recommended** — keep verification on by exporting your pfSense CA certificate, mounting it, and pointing `PFSENSE_CA_BUNDLE` at it:

```yaml
environment:
  PFSENSE_CA_BUNDLE: "/etc/ssl/certs/pfsense-ca.pem"
volumes:
  - ./pfsense-ca.pem:/etc/ssl/certs/pfsense-ca.pem:ro
```

**Otherwise** — set `PFSENSE_VERIFY_SSL=false` to restore the old behaviour. Understand the trade first: this service authenticates with a pfSense API token, so anyone able to intercept the connection can present any certificate and collect that token.

There is one other breaking change — alias names are now capped at 253 characters, and an over-long alias left behind by an earlier version will stop your DNS resolver until you delete it in the webGUI. See [CHANGELOG.md](CHANGELOG.md) for that and for everything else in this release.

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
           PFSENSE_API_TOKEN: "${PFSENSE_API_TOKEN}"
           # Keep TLS verification enabled by default. For self-signed certs,
           # mount a CA bundle and set PFSENSE_CA_BUNDLE to its container path.
           # PFSENSE_VERIFY_SSL: "true"
           # PFSENSE_CA_BUNDLE: "/etc/ssl/certs/pfsense-ca.pem"
           # Uncomment to enable scanning for aliases on startup
           # ADD_ALIASES_ON_STARTUP: "true"
         volumes:
           - /var/run/docker.sock:/var/run/docker.sock
           # Uncomment when using PFSENSE_CA_BUNDLE
           # - ./pfsense-ca.pem:/etc/ssl/certs/pfsense-ca.pem:ro
         restart: unless-stopped
     ```

3. **Start the Service**:
   - Run the following command to start the container:
     ```bash
     docker compose up -d
     ```

4. **Verify Logs**:
   - Check the logs to confirm the container is running and communicating with pfSense:
     ```bash
     docker compose logs -f
     ```

5. **Stop the Service** (Optional):
   - If you need to stop the container:
     ```bash
     docker compose down
     ```
#### Using `docker run`
```bash
docker run \
  --name pfsense-docker-alias \
  -e PFSENSE_HOSTNAME="pfsense.lab.internal" \
  -e PFSENSE_API_TOKEN \
  -e PFSENSE_VERIFY_SSL="true" \
  -e ADD_ALIASES_ON_STARTUP="false" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  ghcr.io/toddawhittaker/pfsense-docker-alias:latest
```

### Notes 📝

- Set `PFSENSE_API_TOKEN` in your shell or Compose `.env` file instead of hardcoding the token in `docker-compose.yaml`.
- Ensure the required environment variables (`PFSENSE_HOSTNAME`, `PFSENSE_API_TOKEN`) are correctly set.
- If using `ADD_ALIASES_ON_STARTUP`, ensure all currently running containers are labeled correctly before starting the service. Startup sync is additive and does not prune stale aliases.
- A single container start applies right away. When several containers start at once — a `docker compose up`, or a startup scan — the changes are batched and applied in one DNS resolver reload rather than one per alias. A lone alias is therefore live in seconds, while a burst of twenty costs two reloads instead of twenty. Tune with `APPLY_QUIET_SECONDS` if your services start staggered over a longer period.
- Replace `pfsense.lab.internal` with the fully qualified hostname or IP address of your pfSense firewall.
- Mounting `/var/run/docker.sock` gives this service broad access to the Docker host. Run it only on trusted hosts and with a pfSense API token scoped as narrowly as your installation allows.


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
   docker compose up -d
   ```

5. **Check Logs**:
   Verify the service is running correctly:
   ```bash
   docker compose logs -f
   ```

## Configuration 🔧

### Environment Variables
Use these environment variables in your `docker-compose.yaml` or `docker run` command to configure `pfsense-docker-alias` with details on your infrastructure.

| Variable Name            | Required | Default | Description                                           |
|--------------------------|----------|---------|-------------------------------------------------------|
| `PFSENSE_HOSTNAME`       | Yes      | None    | Fully qualified domain name of your pfSense instance. |
| `PFSENSE_API_TOKEN`      | Yes      | None    | API token for authenticating with pfSense.            |
| `PFSENSE_VERIFY_SSL`     | No       | `true`  | Validate the pfSense HTTPS certificate. Set to `false` only if certificate validation is not possible. |
| `PFSENSE_CA_BUNDLE`      | No       | None    | Path inside the container to a custom CA bundle for pfSense certificate validation. |
| `ADD_ALIASES_ON_STARTUP` | No       | `false` | Add aliases for currently running labeled containers on startup. |
| `APPLY_QUIET_SECONDS`    | No       | `10`    | Seconds without a new container event before staged DNS changes are applied together. Applying reloads the pfSense DNS resolver and takes a few seconds, so bursts are batched into one reload. |
| `APPLY_MAX_WAIT_SECONDS` | No       | `60`    | Upper bound on how long staged changes wait, so continuous container churn cannot delay them indefinitely. |

### Docker Labels
Use these labels on your services to automatically generate aliases in pfSense DNS.

| Label Name                   | Required | Description                                                           |
|------------------------------|----------|-----------------------------------------------------------------------|
| `pfsense.dns.override`       | Yes      | The **existing** DNS host override in pfSense to associate the alias. Maximum 253 characters (RFC 1035). |
| `pfsense.dns.alias`          | Yes      | The DNS alias to add for this container. Maximum 253 characters (RFC 1035); each dot-separated label is at most 63 characters and may contain only letters, digits, and hyphens. |
| `pfsense.dns.remove_on_stop` | No       | Remove the alias when the container stops or exits. Must be exactly `true`. |
| `pfsense.dns.description`    | No       | Description for the alias. Free text. Unprintable characters are replaced with spaces and the value is capped at 255 characters. |

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
      - "pfsense.dns.description=My nginx webserver"
      - "pfsense.dns.remove_on_stop=true"
```
### Notes 📝

- Replace `caddy.lab.internal` with the fully qualified hostname of your reverse proxy. Make sure it exists as a host override in pfSense.
- Replace `nginx.lab.internal` with the fully qualified hostname of the service you're deploying.
- An alias longer than 253 characters (RFC 1035's limit) is rejected with a warning. No DNS client could resolve such a name anyway, so nothing is lost by refusing it.
- **If an over-long alias already exists in pfSense from an earlier version of this service, delete it in the webGUI now.** It is not harmless leftover configuration: it makes `unbound-checkconf` fail, so the DNS resolver stops on its next reload and every name on the firewall stops resolving, not just that one. This service cannot clean it up for you — the same length rule that blocks creating such an alias also blocks removing it.
- `pfsense.dns.remove_on_stop=true` works with `docker run --rm`. This service records a container's alias configuration when it starts, so a container Docker has already deleted by the time its stop event arrives still has its alias removed. Containers already running before this service starts are only recorded when `ADD_ALIASES_ON_STARTUP` is enabled; without it, a pre-existing `--rm` container that stops may leave its alias behind.

## Contributing 💻

Contributions are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for how to get set up, what has to pass before a pull request, and how to test a change against a real pfSense using the throwaway VM in [`test-env/`](test-env/).

## License 📜

This project is licensed under the MIT License. See the LICENSE file for details.
