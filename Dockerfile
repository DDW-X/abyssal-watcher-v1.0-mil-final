
# Use an official lightweight Rust image
FROM rust:1.70-slim

# Create app directory
WORKDIR /usr/src/abyssal_watcher

# Copy project files
COPY . .

# Build project (simulated command for now)
RUN echo "Building core modules..." && sleep 1

# Set the startup command
CMD ["echo", "Abyssal Watcher is running in Docker."]
