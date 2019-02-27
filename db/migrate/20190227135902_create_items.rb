class CreateItems < ActiveRecord::Migration
  def change
    create_table :items do |t|
      t.string :sku
      t.string :barcode
      t.string :title
      t.string :description
      t.integer :quantity
      t.decimal :costprice
      t.decimal :price
      t.integer :user_id

      t.timestamps null: false
    end
  end
end
