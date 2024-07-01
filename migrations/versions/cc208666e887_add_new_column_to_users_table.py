"""Add new column to users table

Revision ID: cc208666e887
Revises: 
Create Date: 2024-06-23 19:47:03.048790

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'cc208666e887'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('admins', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=50), nullable=False))

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=50), nullable=False))

    with op.batch_alter_table('vets', schema=None) as batch_op:
        batch_op.add_column(sa.Column('role', sa.String(length=50), nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('vets', schema=None) as batch_op:
        batch_op.drop_column('role')

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_column('role')

    with op.batch_alter_table('admins', schema=None) as batch_op:
        batch_op.drop_column('role')

    # ### end Alembic commands ###
