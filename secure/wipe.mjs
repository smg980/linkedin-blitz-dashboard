export function wipePrivateRoot(root) {
  if (!root) return;
  if (typeof root.querySelectorAll === 'function') {
    for (const input of root.querySelectorAll('input, textarea')) input.value = '';
  }
  while (root.firstChild) root.removeChild(root.firstChild);
}
