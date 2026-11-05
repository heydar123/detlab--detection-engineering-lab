# Run it on your computer

Simple steps. You do not need to understand the code. About 10 minutes.

You need two free programs:

- **Python**, version 3.11 or newer. Get it at python.org. On Windows, tick the box "Add python.exe to PATH" when you install it.
- **Visual Studio Code** (VS Code). Get it at code.visualstudio.com.

Nothing else. The project carries everything it needs.

## Windows, step by step

**1. Get the files.** Download the project from GitHub (green **Code** button, then **Download ZIP**), or use the zip you
were given. Right-click the zip, click **Extract All**, then click **Extract**. A folder opens. This is the project folder.

**2. Open the folder in VS Code.** Start VS Code. Click **File**, then **Open Folder**. Choose the project folder and click
**Select Folder**.

Check the list on the left side of VS Code. You should see names like `detlab`, `rules` and `README.md`. If you see only one
folder with a long name, click **File**, **Open Folder** again and choose that inner folder.

**3. Open the terminal.** In VS Code, click **Terminal** at the top, then **New Terminal**. A box opens at the bottom. You
type commands in it.

**4. Start the lab.** Click inside the terminal box. Type this, then press Enter:

```
python -m detlab app
```

Wait a few seconds. Your browser opens a page called **Detection Lab**. If the browser does not open, look in the terminal
for a line that starts with `Open this address in your browser:`. Copy that address into your browser.

**5. Look around.** Start with **Overview**, then **Real recordings**, then **Cases**. Click an alert to see the log events
behind it.

**6. Stop it.** Click inside the terminal box. Press the **Ctrl** key and the **C** key together.

## macOS or Linux

Do the same steps, and type `python3 -m detlab app` in step 4.

## Check that everything works (optional)

Type these in the terminal, one at a time:

```
python -m detlab validate
python -m detlab test-rules
```

The first prints `OK: 32 rules valid`. The second runs the tests written inside the rules and prints how many passed.

To run the full test suite, type `python -m pip install -r requirements.txt` and then `python -m pytest -q`.

## If something goes wrong

| You see | Do this |
|---|---|
| `python is not recognized` | Type `py -m detlab app` instead. If that fails too, install Python again and tick "Add python.exe to PATH". |
| `I cannot find the rules folder` | The terminal is in the wrong folder. Close it, do step 2 again, then open a new terminal. |
| Nothing opens in the browser | Copy the address from the terminal into your browser. |
| The address is not the same as last time | That is fine. If a number is already in use, the app takes the next free one. Use the address in the terminal. |

## What you just ran

A lab for detection engineering: 32 detection rules, made-up logs with attacks planted in them, real public attack
recordings, and the checks that show how far each rule can be trusted. Read the [README](../README.md) for the results and
the limits. It is a lab on made-up and public data, not production experience.
