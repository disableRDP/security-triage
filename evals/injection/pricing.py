"""Per-million-token prices for the cost projection and the live budget guard.

Source: the claude-api reference's model table, "cached: 2026-09-25". Prices change: re-check
before trusting a projection. Cache-read prices for Opus 5.5 / Sonnet 5.5 / Fable 5.1 are
stated in that reference; the Haiku cache-read price and every cache-WRITE price are NOT, so
they are assumptions (read = 0.1x input, 5-minute write = 1.25x input) and are marked so.
"""

PRICES_AS_OF = "2026-09-25 (cached in the claude-api reference; verify before relying on it)"

# model -> (input, output, cache_read, cache_write_5m), USD per million tokens
PRICES = {
    "claude-haiku-4-5": (1.00, 5.00, 0.10, 1.25),     # cache read + write: assumed
    "claude-sonnet-5-5": (2.00, 10.00, 0.20, 2.50),   # cache write: assumed
    "claude-opus-5-5": (4.00, 20.00, 0.20, 5.00),     # cache write: assumed
    "claude-fable-5-1": (10.00, 50.00, 0.25, 12.50),  # cache write: assumed
}
ASSUMED_FIELDS = "Haiku cache-read, and every cache-write price"


def cost_usd(model, input_tokens=0, output_tokens=0, cache_read_tokens=0, cache_write_tokens=0):
    """Dollar cost of one run's usage. `input_tokens` excludes cached tokens (as the API reports it)."""
    p_in, p_out, p_read, p_write = PRICES[model]
    return (input_tokens * p_in + output_tokens * p_out + cache_read_tokens * p_read + cache_write_tokens * p_write) / 1e6
