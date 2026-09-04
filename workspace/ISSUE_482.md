# ISSUE #482: `checkout()` crashes on empty cart

Reported by: @customer-success
Labels: bug, checkout

The `checkout()` helper raises `IndexError` when the cart is empty instead of
returning early with a friendly message.

Repro:

```python
checkout(cart=[])
```

Expected behavior: return early with a friendly "your cart is empty" response.
