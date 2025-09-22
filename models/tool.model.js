// models/tool.model.js - Tool Model

const mongoose = require('mongoose');

const toolSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, 'Tool name is required'],
        unique: true,
        trim: true,
        maxlength: [100, 'Tool name must be less than 100 characters'],
        minlength: [2, 'Tool name must be at least 2 characters']
    },
    description: {
        type: String,
        required: [true, 'Tool description is required'],
        trim: true,
        maxlength: [500, 'Description must be less than 500 characters'],
        minlength: [5, 'Description must be at least 5 characters']
    },
    category: {
        type: String, // Changed from ObjectId to String for simplicity
        required: [true, 'Category is required'],
        enum: [
            'calculator',
            'converter', 
            'generator',
            'analyzer',
            'formatter',
            'validator',
            'planner',
            'tracker',
            'simulator',
            'utility',
            'other'
        ],
        default: 'utility'
    },
    toolType: {
        type: String,
        required: [true, 'Tool type is required'],
        enum: [
            'analytics', 
            'quiz', 
            'planner', 
            'calculator',
            'tracker', 
            'ai-assistant', 
            'simulator',
            'database', 
            'practice', 
            'assessment',
            'utility', 
            'interactive',
            'converter',
            'generator',
            'formatter',
            'validator'
        ],
        default: 'utility'
    },
    icon: {
        type: String,
        trim: true,
        default: 'tool'
    },
    color: {
        type: String,
        default: '#3b82f6',
        match: [/^#([A-Fa-f0-9]{6}|[A-Fa-f0-9]{3})$/, 'Please provide a valid hex color']
    },
    url: {
        type: String,
        trim: true,
        validate: {
            validator: function(v) {
                return !v || /^https?:\/\/.+/.test(v);
            },
            message: 'URL must be a valid HTTP/HTTPS URL'
        }
    },
    isActive: {
        type: Boolean,
        default: true
    },
    isPremium: {
        type: Boolean,
        default: false
    },
    settings: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    features: [{
        name: {
            type: String,
            required: true,
            trim: true
        },
        description: {
            type: String,
            required: true,
            trim: true
        },
        isEnabled: {
            type: Boolean,
            default: true
        }
    }],
    inputFields: [{
        name: {
            type: String,
            required: true
        },
        label: {
            type: String,
            required: true
        },
        type: {
            type: String,
            enum: ['number', 'text', 'select', 'checkbox', 'radio', 'date', 'email', 'url'],
            default: 'text'
        },
        required: {
            type: Boolean,
            default: false
        },
        placeholder: {
            type: String,
            default: ''
        },
        validation: {
            min: Number,
            max: Number,
            pattern: String,
            message: String
        },
        options: [{
            label: String,
            value: mongoose.Schema.Types.Mixed
        }]
    }],
    tags: {
        type: [String],
        default: [],
        validate: {
            validator: function(tags) {
                return tags.length <= 10;
            },
            message: 'Cannot have more than 10 tags'
        }
    },
    createdBy: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: [true, 'Creator is required']
    },
    usageCount: {
        type: Number,
        default: 0,
        min: [0, 'Usage count cannot be negative']
    },
    rating: {
        type: Number,
        default: 0,
        min: [0, 'Rating cannot be negative'],
        max: [5, 'Rating cannot be more than 5']
    },
    ratingCount: {
        type: Number,
        default: 0,
        min: [0, 'Rating count cannot be negative']
    },
    reviews: [{
        user: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'User',
            required: true
        },
        rating: {
            type: Number,
            required: true,
            min: 1,
            max: 5
        },
        comment: {
            type: String,
            maxlength: [500, 'Review comment must be less than 500 characters']
        },
        createdAt: {
            type: Date,
            default: Date.now
        }
    }],
    lastUsed: {
        type: Date,
        default: null
    }
}, {
    timestamps: true,
    toJSON: { 
        virtuals: true,
        transform: function(doc, ret) {
            delete ret.__v;
            return ret;
        }
    },
    toObject: { virtuals: true }
});

// Indexes for performance
toolSchema.index({ category: 1, toolType: 1 });
toolSchema.index({ isActive: 1 });
toolSchema.index({ isPremium: 1 });
toolSchema.index({ createdBy: 1 });
toolSchema.index({ usageCount: -1 });
toolSchema.index({ rating: -1 });
toolSchema.index({ tags: 1 });
toolSchema.index({ name: 'text', description: 'text' }); // Text search index
toolSchema.index({ createdAt: -1 });

// Virtual for popularity score (combination of usage and rating)
toolSchema.virtual('popularityScore').get(function() {
    return (this.usageCount * 0.6) + (this.rating * this.ratingCount * 0.4);
});

// Virtual for average rating display
toolSchema.virtual('displayRating').get(function() {
    return this.ratingCount > 0 ? Math.round(this.rating * 10) / 10 : 0;
});

// Virtual for formatted usage count
toolSchema.virtual('formattedUsageCount').get(function() {
    if (this.usageCount >= 1000000) {
        return Math.round(this.usageCount / 100000) / 10 + 'M';
    } else if (this.usageCount >= 1000) {
        return Math.round(this.usageCount / 100) / 10 + 'K';
    }
    return this.usageCount.toString();
});

// Pre-save middleware to update tags to lowercase
toolSchema.pre('save', function(next) {
    if (this.tags && this.tags.length > 0) {
        this.tags = this.tags.map(tag => tag.toLowerCase().trim()).filter(tag => tag.length > 0);
        // Remove duplicates
        this.tags = [...new Set(this.tags)];
    }
    next();
});

// Instance method to increment usage count
toolSchema.methods.incrementUsage = function() {
    this.usageCount += 1;
    this.lastUsed = new Date();
    return this.save();
};

// Instance method to add review and update rating
toolSchema.methods.addReview = function(userId, rating, comment) {
    // Remove existing review from this user
    this.reviews = this.reviews.filter(review => !review.user.equals(userId));
    
    // Add new review
    this.reviews.push({
        user: userId,
        rating: rating,
        comment: comment
    });
    
    // Recalculate average rating
    const totalRating = this.reviews.reduce((sum, review) => sum + review.rating, 0);
    this.rating = totalRating / this.reviews.length;
    this.ratingCount = this.reviews.length;
    
    return this.save();
};

// Instance method to toggle active status
toolSchema.methods.toggleActiveStatus = function() {
    this.isActive = !this.isActive;
    return this.save();
};

// Static method to get popular tools
toolSchema.statics.getPopularTools = function(limit = 10, category = null) {
    const query = { isActive: true };
    if (category) {
        query.category = category;
    }
    
    return this.find(query)
        .sort({ usageCount: -1, rating: -1 })
        .limit(limit)
        .populate('createdBy', 'username fullName')
        .lean();
};

// Static method to search tools
toolSchema.statics.searchTools = function(searchTerm, filters = {}) {
    const query = { 
        isActive: true,
        ...filters
    };
    
    if (searchTerm) {
        query.$or = [
            { name: { $regex: searchTerm, $options: 'i' } },
            { description: { $regex: searchTerm, $options: 'i' } },
            { tags: { $in: [new RegExp(searchTerm, 'i')] } }
        ];
    }
    
    return this.find(query)
        .sort({ usageCount: -1, rating: -1 })
        .populate('createdBy', 'username fullName')
        .lean();
};

// Static method to get tools by category
toolSchema.statics.getToolsByCategory = function(category, limit = 50) {
    return this.find({ 
        category: category, 
        isActive: true 
    })
    .sort({ usageCount: -1, rating: -1 })
    .limit(limit)
    .populate('createdBy', 'username fullName')
    .lean();
};

// Static method to get tool statistics
toolSchema.statics.getToolStats = async function() {
    const stats = await this.aggregate([
        {
            $group: {
                _id: null,
                totalTools: { $sum: 1 },
                activeTools: { 
                    $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                },
                premiumTools: {
                    $sum: { $cond: [{ $eq: ['$isPremium', true] }, 1, 0] }
                },
                totalUsage: { $sum: '$usageCount' },
                averageRating: { $avg: '$rating' }
            }
        }
    ]);
    
    return stats[0] || {
        totalTools: 0,
        activeTools: 0,
        premiumTools: 0,
        totalUsage: 0,
        averageRating: 0
    };
};

// Static method to get category distribution
toolSchema.statics.getCategoryStats = function() {
    return this.aggregate([
        {
            $group: {
                _id: '$category',
                count: { $sum: 1 },
                activeCount: {
                    $sum: { $cond: [{ $eq: ['$isActive', true] }, 1, 0] }
                },
                totalUsage: { $sum: '$usageCount' },
                averageRating: { $avg: '$rating' }
            }
        },
        {
            $sort: { count: -1 }
        }
    ]);
};

module.exports = mongoose.model('Tool', toolSchema);