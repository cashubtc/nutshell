import random
import flet as f

from cashu.gui.src.models.gui_wallet import GuiMintBalance


class BalancePieChart(f.UserControl):
    bpm: list[GuiMintBalance]
    _colors = [
        f.colors.DEEP_ORANGE_300,
        f.colors.DEEP_ORANGE_400,
        f.colors.DEEP_ORANGE_500,
        f.colors.DEEP_ORANGE_600,
        f.colors.DEEP_ORANGE_700,
        f.colors.DEEP_ORANGE_800,
        f.colors.DEEP_ORANGE_900,
    ]

    def __init__(
        self,
        balance_per_mint: list[GuiMintBalance],
        on_selected=None,
        selected_mint: str = "",
    ):
        self.bpm = balance_per_mint
        self.on_section_selected = on_selected
        self._selected_mint = selected_mint

        super().__init__()

    def build(self):
        return f.PieChart(
            sections_space=1,
            center_space_radius=0,
            expand=True,
            on_chart_event=self._on_chart_event,
            sections=[
                f.PieChartSection(
                    b.percent,
                    title=b.mint_name,
                    title_style=self._build_chart_section_title(b.mint_name),
                    title_position=0.5 if b.percent > 5 else 1.5,
                    color=self._colors[i],
                    radius=135,
                )
                for i, b in enumerate(self.bpm)
            ],
        )

    async def _on_chart_event(self, e: f.PieChartEvent):
        if e.type == "TapUpEvent":
            mint_name = self.bpm[e.section_index].mint_name
            await self.on_section_selected(mint_name)

    def _build_chart_section_title(self, mint_name: str):
        if mint_name == self._selected_mint:
            return f.TextStyle(size=30, color=f.colors.BLUE_900)

        return f.TextStyle(size=25)
