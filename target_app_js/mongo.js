// MongoDB connection for the member routes (connection string comes from the environment)
const { MongoClient } = require('mongodb')

const client = new MongoClient(process.env.MONGODB_URI)
module.exports = { db: client.db('club') }
