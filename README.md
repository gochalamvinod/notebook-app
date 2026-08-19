# Leatherbound Notebook

A private notebook that runs entirely on your own machine — a real open
two-page book, rich text, multiple fonts, embedded images, live link
previews, and a heavy-graphics WebGL (three.js) page-turn, with everything
encrypted on disk.

## Run it

```
npm start
```

(`node_modules` is already included, so this works offline — no `npm install` needed.
If you ever delete `node_modules`, run `npm install` first.)

Then open **http://localhost:3000**.

## First time

You'll be asked to choose a password. This password encrypts your entire
notebook (AES-256-GCM, key derived with scrypt) — it is **never stored
anywhere**, only used in memory to unlock the file each time you start the
server. If you forget it, there is no recovery, by design.

## How your data is protected

- Everything (text, formatting, fonts, images) is saved as one file:
  `data/notebook.enc.json` — and it is always ciphertext. Open it in a text
  editor and you'll see nothing readable.
- The decryption key only ever lives in the server's memory, for as long as
  the server process is running and unlocked.
- **Restarting the server always re-locks the notebook** — you'll need your
  password again. This is intentional: it's what makes "saved even when
  off" mean something.
- You can also lock it manually at any time with the 🔒 button, without
  restarting the server.

## Using it

- **The book itself** shows two real pages side by side, like an open
  hardback, sized to fill most of the window. Whichever page you last
  clicked into is the "active" one the toolbar controls apply to.
- **Fonts & size** — the dropdowns in the toolbar set the font for the
  active page.
- **Bold / italic / underline / align / color / highlight** — apply to
  selected text, like any text editor.
- **🖼 Insert image** — pick a photo; it's automatically resized and embedded
  directly in the page (and encrypted along with everything else). You can
  also just drag an image file straight onto a page.
- **🔗 Live links** — paste a bare URL (or click 🔗 and type one) and the
  notebook does something useful with it automatically:
  - a YouTube/Vimeo link becomes a real embedded, playable video,
  - an image URL (ending in .png/.jpg/etc.) is embedded live from the web,
  - any other link becomes a title/thumbnail preview card, fetched live from
    the page itself (server-side, so it works regardless of the site's CORS
    settings).
  Typing a URL and hitting space/enter auto-links it too. Note: unlike the
  🖼 button, live embedded images and link-preview thumbnails are *not*
  copied into the encrypted file — the page just stores the URL, so viewing
  them later still requires an internet connection and shows whatever's
  live at that URL then. Click a link with Ctrl/Cmd held to open it (a
  plain click just places your cursor, since the page is editable).
- **‹ › arrows** — turn the spread with a real page-flip: a heavy-graphics
  WebGL (three.js) leaf-turn if your browser supports it, or a smooth CSS 3D
  rotation as an automatic fallback if it doesn't.
- **+ Add page / Delete page** — grow or trim the notebook. Adding a page
  fills an empty right-hand slot first; once a spread is full, it opens a
  new one.
- Everything autosaves about a second after you stop typing; the toolbar
  shows "Saved" once it's written to disk.
- **⚙ Settings** lets you change your password at any time.

## Notes on scope

- This is built for personal, local use (`localhost` only) — there's no
  multi-user login system, since it's meant to run on your own machine for
  just you.
- Images are embedded as base64, so a notebook with many large photos will
  grow the data file accordingly; images are auto-downscaled on insert to
  keep things reasonable.
- Port defaults to 3000. To use another port: `PORT=4000 npm start`.
