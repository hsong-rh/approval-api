json.extract! request, :id, :requester, :name, :description, :state, :decision, :reason, :content, :created_at, :updated_at
json.url request_url(request, format: :json)
