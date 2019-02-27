json.extract! item, :id, :sku, :barcode, :title, :description, :quantity, :costprice, :price, :user_id, :created_at, :updated_at
json.url item_url(item, format: :json)
