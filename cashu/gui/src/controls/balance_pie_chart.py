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

    def __init__(self, balance_per_mint: list[GuiMintBalance]):
        self.bpm = balance_per_mint
        super().__init__()

    def build(self):
        return f.PieChart(
            sections_space=1,
            center_space_radius=0,
            expand=True,
            sections=[
                f.PieChartSection(
                    b.percent,
                    title=b.mint_name,
                    title_style=f.TextStyle(size=25),
                    title_position=0.5 if b.percent > 5 else 1.3,
                    color=self._colors[random.randint(0, 6)],
                    radius=135,
                )
                for b in self.bpm
            ],
        )
