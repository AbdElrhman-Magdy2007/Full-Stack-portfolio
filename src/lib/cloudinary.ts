// في @/lib/cloudinary.ts
import { v2 as cloudinary } from "cloudinary";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});

// console.log("Cloudinary Config:", {
//   cloud_name: cloudinary.config().cloud_name,
//   api_key: cloudinary.config().api_key,
//   api_secret: cloudinary.config().api_secret ? "[hidden]" : undefined,
// });

export default cloudinary;