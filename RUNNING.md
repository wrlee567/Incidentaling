# How to run Incidentaling on your own computer

A beginner-friendly, copy-paste guide. **No Docker needed.** You'll start two things:
the **backend** (the "brain" that detects and responds to attacks) and the **frontend**
(the website you click around in).

---

## Step 0 — One-time setup: install the tools

You need two free programs. Check if you already have them by opening a terminal and typing:

```
python3 --version
node --version
```

- If each prints a version number (e.g. `Python 3.11.x`, `v22.x`), you're good.
- If not, install them:
  - **Python:** https://www.python.org/downloads/  (get version 3.11 or newer)
  - **Node.js:** https://nodejs.org/  (get the "LTS" version)

> **Where's the terminal?**
> - **Mac:** press `Cmd+Space`, type "Terminal", hit Enter.
> - **Windows:** press the Start button, type "PowerShell", hit Enter.
> - **Linux:** you know where it is. 🙂

---

## Step 1 — Get the code onto your computer

If you haven't already, download the project from GitHub:

```
git clone https://github.com/wrlee567/Incidentaling.git
cd Incidentaling
git checkout claude/zealous-keller-6Ppea
```

(If you already have the folder, just `cd` into it.)

---

## Step 2 — Start the backend (the brain)

Open a terminal and run these **once** to set it up:

```
cd backend
python3 -m venv .venv
```

Now "activate" it (this command is different per operating system):

- **Mac / Linux:**
  ```
  source .venv/bin/activate
  ```
- **Windows (PowerShell):**
  ```
  .venv\Scripts\Activate.ps1
  ```

Then install the dependencies and start it:

```
pip install -r requirements.txt
uvicorn app.api.main:app
```

✅ **Success looks like:** a message saying `Uvicorn running on http://127.0.0.1:8000`.
**Leave this terminal window open and running** — it's the brain. Closing it stops the backend.

> Want to see it work without the website? Visit **http://localhost:8000/docs** in your
> browser — that's an auto-generated control panel for every backend feature.

---

## Step 3 — Start the frontend (the website)

Open a **second** terminal window (keep the first one running!) and run:

```
cd Incidentaling/frontend
npm install
npm run dev
```

✅ **Success looks like:** a message with `Local: http://localhost:3000`.

---

## Step 4 — Use it!

Open **http://localhost:3000** in your web browser. You'll see the dashboard. Try this:

1. Click **"Inject ransomware"** — this simulates an attack hitting fake computers.
2. Click **"Run detection"** — the SIEM (the detective) finds the attack and raises alerts.
3. Click **"SOAR respond"** — the system automatically fights back (you'll see hosts get
   isolated and bad IPs blocked in the "Containment state" panel).

Then click **"Playbook Editor"** in the left sidebar to see the visual attack-response
flowchart you can drag around.

---

## How to stop everything

In each terminal window, press **`Ctrl + C`**. That's it.

## How to start it again later

- Backend: `cd backend`, activate (`source .venv/bin/activate`), then `uvicorn app.api.main:app`
- Frontend: `cd frontend`, then `npm run dev`

(You only do the `python -m venv`, `pip install`, and `npm install` steps **once**. After
that, just activate + run.)

---

## Something went wrong?

- **Website says it can't reach the backend / shows a red error:** the backend (Step 2)
  isn't running, or got closed. Restart it.
- **`command not found: python3`:** try `python` instead of `python3`.
- **`command not found: npm`:** Node.js isn't installed — see Step 0.
- **Port already in use:** something else is using port 8000 or 3000. Close other apps,
  or restart your computer, and try again.

---

## Bonus: see it run with no website at all

If you just want to watch the whole attack→detect→respond story print out in the terminal:

```
cd backend
source .venv/bin/activate    # (or the Windows version)
python demo.py
```
