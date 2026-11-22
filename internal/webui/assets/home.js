const instruction = document.getElementById("setup-text");
const status = document.getElementById("status");

document.getElementById("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(instruction.value);
    status.textContent = "Copied.";
  } catch {
    instruction.focus();
    instruction.select();
    status.textContent = "Select and copy the text above.";
  }
});
