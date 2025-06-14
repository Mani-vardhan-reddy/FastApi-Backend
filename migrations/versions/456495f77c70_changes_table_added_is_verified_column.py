"""Changes table Added Is_verified column

Revision ID: 456495f77c70
Revises: e40da58dbc96
Create Date: 2025-06-10 14:54:22.053444

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '456495f77c70'
down_revision: Union[str, None] = 'e40da58dbc96'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('admin', sa.Column('is_verified', sa.Boolean(), nullable=True))
    op.add_column('user', sa.Column('is_verified', sa.Boolean(), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    """Downgrade schema."""
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('user', 'is_verified')
    op.drop_column('admin', 'is_verified')
    # ### end Alembic commands ###
