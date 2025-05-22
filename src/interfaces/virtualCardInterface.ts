export interface VirtualCard {
    cardNumber: string;     // 16-digit number
    cvv: string;           // 3-digit security code
    expiryDate: Date;      // Card expiry date
}

export interface VirtualCardCreationRequest {
    customerId: string;    // ID of the customer requesting the card
}

export interface VirtualCardResponse extends VirtualCard {
    id: string;           // Unique identifier for the virtual card
    createdAt: Date;      // Timestamp of card creation
    status: 'ACTIVE' | 'INACTIVE' | 'EXPIRED';
}