"""Sentinel enforcement adapters.

Adapters translate a specific agent/gateway surface onto sentinel.core
decisions. An adapter is NOT the trust boundary by itself; production
enforcement layers native hooks, proxies and credential authorities on top
(see ARCHITECTURE.md).
"""
