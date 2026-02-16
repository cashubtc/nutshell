"""Tests for wallet batch minting (NUT-333)."""

from cashu.core.mint_info import MintInfo


class TestMintInfoBatchSupport:
    """Tests for MintInfo batch minting methods."""

    def test_supports_batch_mint_without_nuts(self):
        """Test that supports_batch_mint returns False when nuts is None."""
        mint_info = MintInfo.model_construct(nuts=None)
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_supports_batch_mint_without_batch_nut(self):
        """Test that supports_batch_mint returns False when NUT-333 not supported."""
        mint_info = MintInfo.model_construct(nuts={})
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_supports_batch_mint_with_supported_method(self):
        """Test that supports_batch_mint returns True for supported method."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11", "bolt12"]}})
        assert mint_info.supports_batch_mint("bolt11") is True
        assert mint_info.supports_batch_mint("bolt12") is True

    def test_supports_batch_mint_with_unsupported_method(self):
        """Test that supports_batch_mint returns False for unsupported method."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"]}})
        assert mint_info.supports_batch_mint("bolt12") is False

    def test_supports_batch_mint_with_empty_methods(self):
        """Test that supports_batch_mint returns False when methods list is empty."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": []}})
        assert mint_info.supports_batch_mint("bolt11") is False

    def test_get_max_batch_size_without_nuts(self):
        """Test that get_max_batch_size returns 0 when nuts is None."""
        mint_info = MintInfo.model_construct(nuts=None)
        assert mint_info.get_max_batch_size() == 0

    def test_get_max_batch_size_without_batch_nut(self):
        """Test that get_max_batch_size returns 0 when NUT-333 not supported."""
        mint_info = MintInfo.model_construct(nuts={})
        assert mint_info.get_max_batch_size() == 0

    def test_get_max_batch_size_with_value(self):
        """Test that get_max_batch_size returns the configured value."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"], "max_batch_size": 50}})
        assert mint_info.get_max_batch_size() == 50

    def test_get_max_batch_size_without_max(self):
        """Test that get_max_batch_size returns 0 when max_batch_size not set."""
        mint_info = MintInfo.model_construct(nuts={333: {"methods": ["bolt11"]}})
        assert mint_info.get_max_batch_size() == 0
