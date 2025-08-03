# Use a specific Node.js version for reproducibility
FROM node:20-slim AS base

# Install PowerShell
# See https://learn.microsoft.com/en-us/powershell/scripting/install/install-debian?view=powershell-7.4
RUN apt-get update && apt-get install -y curl wget apt-transport-https && \
    apt-get update && \
    apt-get install -y --no-install-recommends gnupg && \
    wget -q "https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb" && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y powershell

# Set up the working directory
WORKDIR /app

# --- Build Stage ---
FROM base AS build

# Copy all files
COPY . .

# Install dependencies
RUN npm install

# Build the project
RUN npm run build

# --- Final Stage ---
FROM base AS final

# Set environment variables for computer name or IP
ARG COMPUTER_NAME
ARG IP_ADDRESS
ENV COMPUTER_NAME=${COMPUTER_NAME}
ENV IP_ADDRESS=${IP_ADDRESS}

# Copy the built application from the build stage
COPY --from=build /app/build ./build
COPY --from=build /app/src ./src
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/package.json .

# Expose the port the app runs on
# The current application uses stdio, so no port is exposed.
# If you switch to a different transport, you may need to expose a port.
# EXPOSE 3000

# Start the application
CMD ["node", "build/index.js"]
