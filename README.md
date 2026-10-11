# Instance Switcher
Instance Switcher lets you change instances on discord ios by holding your screen with 3 fingers

## Encrypted messages (meowcord / fosscord-e2ee v1)
- More... > "Unlock encrypted messages..." (password or recovery code, used once, not saved) unlocks your key backup, registers this install as an encryption device and keeps only its own keys in the Keychain.
- Incoming encrypted messages and attachments are decrypted. Text messages in encrypted conversations are encrypted and signed before they leave the app.
- If a conversation is encrypted and a message can't be sealed (unsupported content, unverifiable keys, a changed safety number, no network), it is not sent at all; nothing is ever sent as plain text.
- Not supported yet: sending files, stickers, polls and forwards in encrypted conversations, editing sent encrypted messages, and verifying signatures on incoming messages. If you unlocked with an older version, unlock again to enable sending.
