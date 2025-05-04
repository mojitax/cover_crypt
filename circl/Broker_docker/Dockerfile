# Use an official Golang runtime as a base image
FROM golang:latest

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy the source code into the container
COPY . .

# Download the dependencies
RUN go mod download
RUN go get github.com/IBM/sarama
RUN go get golang.org/x/crypto/blake2b@v0.19.0
# Build the Go app
#RUN go build -o main .

# Expose port 8080 to the outside world
EXPOSE 8080
EXPOSE 9092
# Command to run the executable
CMD ["/bin/bash"]
