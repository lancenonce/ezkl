# We are using Rust nightly to build the project
FROM rustlang/rust:nightly

# We now set the working directory
WORKDIR /

# We now copy the Cargo.toml and Cargo.lock files to the working directory
COPY Cargo.toml Cargo.lock ./

# Create a dummy main.rs
RUN mkdir src && echo "fn main() {}" > src/main.rs

# Build dependencies
RUN cargo build --release

# Remove dummy main.rs
RUN rm -rf src/main.rs

# Copy the rest of the source code to the container
COPY . .

# Buidl
RUN cargo build --release

# We need a symlink to the binary
RUN ln -s /target/release/ezkl /target/release/ezkl

EXPOSE 8080

# Entry point for the container
CMD ["ezkl"]