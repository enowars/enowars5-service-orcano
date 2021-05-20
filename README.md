# Orcano
Calculator app running as a GameCube executable in the Dolphin emulator.

## How to build
### Build Dolphin
```bash
dolphin/build.sh
```

### Build image
```bash
image/build.sh && image/deploy.sh
```

### Run service
```bash
cd service && docker-compose up --build
```