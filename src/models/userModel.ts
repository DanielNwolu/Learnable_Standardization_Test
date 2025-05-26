import mongoose, { Schema } from 'mongoose';
import { User } from '../interfaces/userInterface';
import bcrypt from 'bcrypt';

const userSchema = new Schema(
  {
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name should not exceed 50 characters'],
      minlength: [2, 'First name should be at least 2 characters']
    },
    surname: {
      type: String,
      required: [true, 'Surname is required'],
      trim: true,
      maxlength: [50, 'Surname should not exceed 50 characters'],
      minlength: [2, 'Surname should be at least 2 characters']
    },
    accountNumber: {
    type: String,
    required: [true, 'Account number is required'],
    unique: true,
    validate: {
      validator: function(v: string) {
        return /^\d{10}$/.test(v); // Validates exactly 10 digits
      },
      message: (props: { value: string }) => `${props.value} is not a valid account number! Must be 10 digits.`
    }
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      trim: true,
      lowercase: true,
      validate: {
        validator: function(v: string) {
          return /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/.test(v);
        },
        message: props => `${props.value} is not a valid email address!`
            }
          },
          phoneNumber: {
            type: String,
            required: [true, 'Phone number is required'],
            trim: true,
            validate: {
        validator: function(v: string) {
          // Allow any string format since it will be hashed
          return typeof v === 'string' && v.length > 0;
        },
        message: props => `Phone number must be a non-empty string`
            }
          },
          dateOfBirth: {
          type: Date,
          required: [true, 'Date of birth is required'],
          validate: {
            validator: function(v: Date) {
        return v <= new Date() && v >= new Date('1900-01-01');
      },
      message: 'Please provide a valid date of birth'
    }
    },
  },
  {
    timestamps: true,
    versionKey: false
  }
);


// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword: string): Promise<boolean> {
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model<User>('User', userSchema);
export default User;