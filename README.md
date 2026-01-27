Add bsbf feed to the bottom of `feeds.conf.default`:
```
src-git bsbf https://github.com/bondingshouldbefree/bsbf-client-scripts.git
```

Refresh feeds and install bsbf feed
```
./scripts/feeds update && ./scripts/feeds install -a
```
