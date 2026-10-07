export interface Example {
  id: string;
  label: string;
  text: string;
}

export const EXAMPLES: Example[] = [
  {
    id: "harmless",
    label: "Looks harmless",
    text: "Your monthly statement is ready. No action is required."
  },
  {
    id: "prize_bait",
    label: "Prize bait",
    text: "Congratulations, you won a reward. Confirm your account details using the link."
  },
  {
    id: "delivery_trap",
    label: "Delivery trap",
    text: "Your delivery could not be completed. Enter the OTP on the verification page."
  },
  {
    id: "otp_grab",
    label: "OTP grab",
    text: "Your account will be suspended. Verify your password and OTP immediately using this link."
  },
  {
    id: "account_scare",
    label: "Account scare",
    text: "Please confirm your contact information in the customer portal before the review window closes."
  }
];
