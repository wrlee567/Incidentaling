# Putting Incidentaling online (Vercel + Render)

A click-by-click guide. You'll deploy the **backend (brain) on Render** first, get its web
address, then deploy the **frontend (website) on Vercel** and point it at the backend.

Both are **free** and you sign in with your GitHub account. Total time: ~15 minutes.

> **Do this in order** — the website needs the backend's address, so the backend goes first.

---

## Part 1 — Deploy the backend on Render

1. Go to **https://render.com** and click **Get Started** → **Sign in with GitHub**.
   Approve the access it asks for.
2. In the Render dashboard, click **New +** (top right) → **Blueprint**.
3. Find and select your **`Incidentaling`** repository from the list.
   - If you don't see it, click **"Configure account"** and give Render access to the repo.
4. Render will detect the `render.yaml` file I added and show a service called
   **`incidentaling-backend`**. Click **Apply** (or **Create Services**).
5. Wait a few minutes while it builds. When it finishes, you'll see a green **"Live"** badge.
6. **Copy the web address** at the top of the service page. It looks like:
   ```
   https://incidentaling-backend.onrender.com
   ```
   **Save this** — you need it in Part 2.

✅ **Test it:** open `https://YOUR-BACKEND-ADDRESS/health` in your browser. You should see
`{"status":"ok","version":"0.1.0"}`. (The first load may take ~50 seconds if it was asleep.)

---

## Part 2 — Deploy the frontend on Vercel

1. Go to **https://vercel.com** and click **Sign Up** / **Continue with GitHub**.
2. Click **Add New...** → **Project**.
3. Find your **`Incidentaling`** repo and click **Import**.
4. **Important — set the Root Directory:** click **Edit** next to "Root Directory" and
   choose the **`frontend`** folder. (This tells Vercel the website lives in that subfolder.)
5. Expand the **Environment Variables** section and add one:
   - **Name:** `NEXT_PUBLIC_API_BASE`
   - **Value:** the backend address you copied in Part 1, e.g.
     `https://incidentaling-backend.onrender.com`
     (no trailing slash)
6. Click **Deploy** and wait a minute or two.
7. When it's done, Vercel gives you a website address like
   `https://incidentaling.vercel.app`. Click it!

---

## Part 3 — Use it

Open your Vercel website address. Click **Inject ransomware → Run detection → SOAR respond**
and watch the containment panel update.

> **First click feels slow?** That's the free Render backend waking up from sleep
> (~50 seconds). After it's awake, everything is fast. It goes back to sleep after ~15
> minutes of no use.

---

## Updating later

Both Render and Vercel are connected to your GitHub. **Any time you push new code to your
branch, they automatically rebuild and redeploy.** Nothing extra to do.

---

## Troubleshooting

- **Website loads but shows a red "can't reach backend" error:**
  - The backend may be asleep — wait ~50s and refresh.
  - Double-check the `NEXT_PUBLIC_API_BASE` value in Vercel (Settings → Environment
    Variables) exactly matches your Render address, with **no trailing slash**. If you
    change it, you must **redeploy** (Vercel → Deployments → ⋯ → Redeploy).
- **Render build fails:** open the build logs on Render and paste them to me.
- **Vercel can't find the website / build fails:** make sure **Root Directory** is set to
  `frontend` (Vercel → Settings → General → Root Directory).
