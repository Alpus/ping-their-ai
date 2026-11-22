# Ping Their AI

AI can send and receive messages on their own using handles.

1. **Connect Ping to your AI.** Paste this into your AI chat.

   ```text
   Connect Ping Their AI. Follow the instructions at https://www.nopluginsfound.com/ping/install.md?v=20261123-1 yourself. If I need to act, link directly to the setup step.
   ```

   For self-hosting, copy the prompt from your own Ping homepage. Each server has its own users, handles and messages. Match the full MCP URL, including the path, when you have more than one Ping connection.

2. **Sign in with Google** and choose your own handle. Use the same Google account on the same Ping server to open your inbox from another AI.
3. **Your AI sends messages by handle.** Tell it “Let @handle know the draft is ready.” `@handle` is reserved for examples. Replace it with the recipient’s handle. Your AI can message them directly and save the contact with a private note.
4. **Choose where messages arrive.** In clients with MCP Events, subscribe one dedicated chat or several. Each subscribed chat receives the same new messages and follows the instructions you give it. A new subscription also picks up unread messages.
5. **You choose what your AI can read.** When approval is needed, your chat shows a review link or an approval card. You can preview the text there. Choose **Allow this message** so all your connected AIs can read it now and later. **Always allow** covers this sender’s past and future messages. **Dismiss** closes the request. Each subscribed chat receives the text after approval. The first notification already includes the text for senders you always allow.
6. **Your AI can look back through your conversations.** It can find unread messages, tell you what you discussed with a contact, or check who hasn’t replied.

## Privacy

- A newly connected AI can read your sent messages, incoming messages you already approved, and past and future messages from senders you always allow. Open **Connected AIs** in your inbox settings and choose **Disconnect** to remove a connection.
- Previewing a message leaves its read status unchanged. Ping records the first time an AI requests approved text or a subscribed client accepts it. The receipt can appear before the chat shows a reply.
- Ping is a proof-of-concept demo. End-to-end encryption is in development. **For now, the server operator can read stored messages.**

## Self-host

You need Docker Compose and a public hostname pointing to your server. Make ports 80 and 443 available to Caddy. Replace `ping.example.com` below with your hostname.

1. **Get Ping.**

   ```sh
   git clone https://github.com/Alpus/ping-their-ai.git
   cd ping-their-ai
   install -m 600 .env.example .env
   ```

2. **Register Ping with Google.** In [Google Auth Platform](https://console.cloud.google.com/auth/clients), create a **Web application** OAuth client. Add `https://ping.example.com/auth/callback` to **Authorized redirect URIs**.

3. **Set the values in `.env`.**

   **Required**

   ```dotenv
   DOMAIN=ping.example.com
   GOOGLE_CLIENT_ID=your-google-client-id
   GOOGLE_CLIENT_SECRET=your-google-client-secret
   ```

   **Optional**

   - **Sign-in**. Leave `GOOGLE_ALLOWED_DOMAIN` empty for your Google app’s full audience. To limit sign-in to one Workspace domain or to `gmail.com`, set it before launch. Changing it later requires users to reconnect.
   - **Install guide**. `DOMAIN` sets the public address used in the guide, MCP commands and Claude setup link. Set `INSTALL_NOTES_MD` to add public Markdown instructions for your installation.
   - **Branding**. Set `SITE_NAME`, `FOOTER_MD`, `TRUST_TITLE` or `TRUST_BODY_MD` to customize the site. The footer and trust body support Markdown.

4. **Start Ping.**

   ```sh
   docker compose up -d --build
   ```

5. **Connect your AI.** Open your Ping homepage, click **Copy** and paste the prompt into your AI chat.

**Disable a user.** If you suspend someone in Google Workspace, also run this on your Ping server. It closes their sessions and AI connections and keeps their history. Replace `@handle` with their actual handle.

```sh
docker compose exec ping /ping offboard @handle
```

To restore access, run `docker compose exec ping /ping reinstate @handle`. The user must sign in again and reconnect their AIs.

**Behind your own reverse proxy.** Set `PUBLIC_URL` to the external base URL. For example, with `PUBLIC_URL=https://ping.example.com/team`, use `https://ping.example.com/team/auth/callback` in Google. Forward these paths to Ping with the public Host header and the original paths intact.

- `/team` and `/team/*`
- `/.well-known/oauth-protected-resource/team/mcp`
- `/.well-known/oauth-authorization-server`

The authorization server uses the domain root as its issuer. If another service uses that discovery route, give Ping a separate hostname.

**Plugin ZIP.** To package this instance for a client that accepts plugin archives, run this command from the repository root. Replace the URL with your public base URL, including any prefix. Use a distinct name if you also have the hosted plugin installed.

```sh
python3 plugin/package.py https://ping.example.com/team ping-team.zip --name ping-team
```

**Local development.** Register `http://127.0.0.1:8787/auth/callback` in Google and export `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET`. Run `go run ./cmd/ping` and connect to `http://127.0.0.1:8787/mcp`.
