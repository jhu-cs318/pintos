# The Foolproof Pintos Setup

Manually building the legacy 32-bit toolchain on modern hardware causes SSE instruction traps during the kernel boot process. Using this specific pre-built Docker image entirely bypasses those compiler mismatches.

## 1. Download the Source (Kubuntu Host Terminal)
```bash
git clone https://github.com/jhu-cs318/pintos.git ~/pintos
```

## 2. Launch the Environment (Kubuntu Host Terminal)
This mounts your local code into the container.
```bash
docker run -it --rm --name pintos-env --mount type=bind,source=$HOME/pintos,target=/home/PKUOS/pintos pkuflyingpig/pintos bash
```

## 3. Enable the Commands (Docker Terminal)
Run this every time you start the container.
```bash
export PATH=/home/PKUOS/pintos/src/utils:$PATH
```

## 4. Compile and Verify (Docker Terminal)
```bash
cd /home/PKUOS/pintos/src/threads
make
cd build
pintos -- run alarm-multiple
```
*(Press `Ctrl + C` when the test finishes to get your prompt back).*

## Daily Workflow Summary
* **Write code:** Use VS Code on your Kubuntu host in the `~/pintos` folder.
* **Compile/Test:** Run `make` and `pintos` inside the Docker terminal.
* **Save progress:** Use GitHub Desktop on your Kubuntu host.
* **Quit:** Type `exit` in Docker. Your code stays safely on your host.
