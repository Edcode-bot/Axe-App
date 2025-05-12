const mongoose = require('mongoose');

const PropertySchema = new mongoose.Schema({
  name: { type: String, required: true },
  address: String,
  landlord: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  tenants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }]
});

module.exports = mongoose.model('Property', PropertySchema);
