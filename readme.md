# Yunzhijia Open API Decryption Plugin
Yunzhijia Open API Request Body Decryption.

## Configuration

To configure this plugin you should add its configuration to the Traefik dynamic configuration as explained [here](https://docs.traefik.io/getting-started/configuration-overview/#the-dynamic-configuration).
The following snippet shows how to configure this plugin with the File provider in TOML and YAML:
Static:
```toml
[experimental.plugins.yzjapidecryption]
  modulename = "github.com/cnmaple/yzj-api-decryption"
  version = "v1.0.0"
```

Dynamic:

```toml
[http.middlewares]
  [http.middlewares.my-yzjapidecryption.plugin.yzjapidecryption]
    CloudFlowKey = "Your Yzj API CloudFlowKey"
```

```yaml
http:
  middlewares:
   my-yzjapidecryption:
      plugin:
        yzjapidecryption:
          CloudFlowKey: Your Yzj API CloudFlowKey
```

### Options

#### CloudFlowKey (`CloudFlowKey`)

The Yzj Open API CloudFlowKey