# nrf70

`no_std` system-mode nRF7002 driver with an embassy-net data plane and a
WPA2-Personal supplicant.

```rust,ignore
let (wifi, runner, device, host_irq) =
    nrf70::new_with_data_plane(resources, platform, net_state);
spawner.spawn(wifi_runner(runner)?);

wifi.initialize(mac, nrf70::Country::new(*b"US")?).await?;
wifi.connect(request).await?;
// Pass `device` to embassy-net.
```

`Bus::random_u8` must be backed by a TRNG. Reapply
`Wifi::configure_coex` after `initialize` and every firmware restart.
