# We are using Rust nightly to build the project
FROM rustlang/rust:nightly

# We now set the working directory
WORKDIR /

# Copy the source files into the container
COPY . .

# Buidl
RUN cargo build --release

# Add the target/release folder to the PATH
ENV PATH="/target/release:${PATH}"

EXPOSE 8080

# Entry point for the container
CMD ["ezkl"]